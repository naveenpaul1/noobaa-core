/* Copyright (C) 2016 NooBaa */
'use strict';

const _ = require('lodash');
const pkg = require('../../package.json');
const fs = require('fs');
const dbg = require('../util/debug_module')(__filename);
const spawn = require('child_process').spawn;
const fs_utils = require('../util/fs_utils');
const P = require('../util/promise');
const os_utils = require('../util/os_utils');
const config = require('../../config');
const promise_utils = require('../util/promise_utils');
const phone_home_utils = require('../util/phone_home');
const argv = require('minimist')(process.argv);
const mongo_client = require('../util/mongo_client');
const net_utils = require('../util/net_utils');

const TMP_PATH = '/tmp';
const EXTRACTION_PATH = `${TMP_PATH}/test`;
const NEW_TMP_ROOT = `${EXTRACTION_PATH}/noobaa-core`;
const PACKAGE_FILE_NAME = 'new_version.tar.gz';
const CORE_DIR = "/root/node_modules/noobaa-core";
const SPAWN_SCRIPT = `${NEW_TMP_ROOT}/src/deploy/NVA_build/two_step_upgrade_checkups_spawn.sh`;
const ERRORS_PATH = `${TMP_PATH}/new_tests_errors.json`;

const ERROR_MAPPING = {
    COULD_NOT_COPY_PACKAGE: 'Failed to prepare the package for extraction, try to re-download the upgrade package and upload again.',
    COULD_NOT_RUN_TESTS: 'Failed to perform pre-upgrade tests, try to re-download the upgrade package and upload again.',
    PACKAGE_JSON_NOT_EXISTS: 'Uploaded package is not a NooBaa upgrade package, try to re-download the upgrade package and upload again.',
    COULD_NOT_EXTRACT_VERSION: 'Uploaded package is not a NooBaa upgrade package, try to re-download the upgrade package and upload again.',
    MAJOR_VERSION_CHANGE: 'Upgrade from the current version to the uploaded version is not supported.',
    CANNOT_DOWNGRADE: 'Downgrade to an older version is not supported.',
    INTERNET_CONNECTIVITY: 'Failed to verify internet connectivity. Check network connectivity or set a proxy address.',
    COULD_NOT_GET_RAW_STORAGE: 'Failed to perform pre-upgrade tests.',
    LOCAL_HARDDRIVE_MEMORY: 'Not enough hard drive space on server required for upgrade, at leaset 300MB is required per server. Please increase local disk.',
    PACKAGE_EXTRACTION: 'Failed to extract NooBaa upload package. try to re-download the upgrade package and upload again.',
    PACKAGE_INSTALLATION_TIMEOUT: 'Failed on pre-upgrade packages.',
    COULD_NOT_EXTRACT_PARAMS: 'Failed to perform pre-upgrade tests.',
    CANNOT_UPGRADE_WITHOUT_SYSTEM: 'Failed to perform pre-upgrade tests due to no system on the server.',
    COULD_NOT_INSTALL_PACKAGES: 'Failed on pre-upgrade packages.',
    NTP_TIMESKEW_FAILED: 'The difference between the server time and a web NTP server time is too large.',
    NTP_COMMUNICATION_ERROR: 'Failed to check time skew, please configure NTP server or verify internet connectivity.',
    UNKNOWN: 'Failed with an internal error.'
};

let staged_package = 'UNKNOWN';

class ExtractionError extends Error {}
class VersionMismatchError extends Error {}
class NewTestsError extends Error {}

function pre_upgrade(params) {
    dbg.log0('UPGRADE:', 'pre_upgrade called with params =', params);
    return P.resolve()
        .then(() => promise_utils.exec(`cp -f ${params.upgrade_path} ${TMP_PATH}/${PACKAGE_FILE_NAME}`, {
            ignore_rc: false,
            return_stdout: true,
            trim_stdout: true
        }))
        .catch(err => {
            dbg.error('pre_upgrade: package copying failed', err);
            throw new ExtractionError('COULD_NOT_COPY_PACKAGE');
        })
        .then(() => pre_upgrade_checkups(params))
        .then(() => {
            dbg.log0('new_pre_upgrade spawn');
            // TODO: Should probably do some sort of timeout on the spawn or something
            // Since we already had problems of it just getting stuck and not returning
            return promise_utils.exec(`chmod 777 ${SPAWN_SCRIPT}; ${SPAWN_SCRIPT}`, {
                    ignore_rc: false,
                    return_stdout: true,
                    trim_stdout: true
                })
                .catch(err => {
                    dbg.error('new_pre_upgrade spawn had errors', err);
                    return fs.readFileAsync(ERRORS_PATH)
                        .catch(err_file => {
                            dbg.log0('could not read error file', err_file);
                            throw new Error('COULD_NOT_RUN_TESTS');
                        })
                        .then(errors => {
                            dbg.log0('found errors in spawn: ', String(errors));
                            throw new NewTestsError(JSON.parse(errors).message);
                        });
                });
        })
        .then(() => _.omitBy({
            result: true,
            tested_date: Date.now(),
            staged_package: staged_package || 'UNKNOWN'
        }, _.isUndefined))
        .catch(error => {
            let err_message = ERROR_MAPPING[error.message] || ERROR_MAPPING.UNKNOWN;
            dbg.error('pre_upgrade: HAD ERRORS', error);
            if (error instanceof ExtractionError) { //Failed in extracting, no staged package
                staged_package = 'UNKNOWN';
            }
            if (error instanceof NewTestsError) {
                err_message = error.message;
            }
            return _.omitBy({
                result: false,
                error: err_message,
                tested_date: Date.now(),
                staged_package: staged_package || 'UNKNOWN'
            }, _.isUndefined);
        });
}


function do_upgrade(upgrade_file, is_clusterized, err_handler) {
    try {
        err_handler = err_handler || dbg.error;
        dbg.log0('UPGRADE file', upgrade_file, 'upgrade.js path:', process.cwd() + '/src/deploy/NVA_build');
        var fsuffix = new Date()
            .toISOString()
            .replace(/T/, '-')
            .substr(5, 11);
        var fname = '/var/log/noobaa_deploy_out_' + fsuffix + '.log';
        var stdout = fs.openSync(fname, 'a');
        var stderr = fs.openSync(fname, 'a');
        let cluster_str = is_clusterized ? 'cluster' : ' ';
        dbg.log0('command: /usr/local/bin/node ',
            process.cwd() + '/src/upgrade/upgrade.js --from_file ' + upgrade_file, '--fsuffix', fsuffix, '--cluster_str', cluster_str);
        let upgrade_proc = spawn('nohup', [
            '/usr/local/bin/node',
            process.cwd() + '/src/upgrade/upgrade.js',
            '--from_file', upgrade_file,
            '--fsuffix', fsuffix,
            '--cluster_str', cluster_str
        ], {
            detached: true,
            stdio: ['ignore', stdout, stderr],
            cwd: process.cwd()
        });
        upgrade_proc.on('exit', (code, signal) => {
            // upgrade.js is supposed to kill this node process, so it should not exit while
            // this node process is still running. treat exit as error.
            if (code) {
                const err_msg = `upgrade.js process was closed with code ${code} and signal ${signal}`;
                err_handler(err_msg);
            }
        });
        upgrade_proc.on('error', err_handler);
    } catch (err) {
        err_handler(err);
    }
}

function test_ntp_timeskew(ntp_server) {
    return net_utils.get_ntp_time({ server: ntp_server })
        .catch(err => {
            dbg.error('test_ntp_timeskew failed', err);
            throw new Error('NTP_COMMUNICATION_ERROR');
        })
        .then(date => {
            const FIFTEEN_MINUTES_IN_MILLISECONDS = 900000;
            if (Math.abs(date.getTime() - Date.now()) > FIFTEEN_MINUTES_IN_MILLISECONDS) {
                throw new Error('NTP_TIMESKEW_FAILED');
            }
        });
}

function test_major_version_change() {
    const get_version = `tar -zxvOf ${TMP_PATH}/${PACKAGE_FILE_NAME} noobaa-core/package.json | grep version | awk '{print $2}'`;
    const check_exists = `tar -tf ${TMP_PATH}/${PACKAGE_FILE_NAME} | grep noobaa-core/package.json`;
    return promise_utils.exec(check_exists, {
            ignore_rc: false,
            return_stdout: true,
            trim_stdout: true
        }).catch(err => {
            dbg.error('test_major_version_change package.json not exists', err);
            throw new Error('PACKAGE_JSON_NOT_EXISTS');
        })
        .then(() => promise_utils.exec(get_version, {
            ignore_rc: false,
            return_stdout: true,
            trim_stdout: true
        }).catch(err => {
            dbg.error('Major change extraction had errors', err);
            throw new Error('COULD_NOT_EXTRACT_VERSION');
        }))
        .then(ver => {
            dbg.log0('new package version is', ver);
            staged_package = ver.replace(/[",]/g, '');
            const [staged_major, staged_minor, staged_patch] = staged_package.split('-')[0].split('.').map(str => Number(str));
            const [current_major, current_minor, current_patch] = pkg.version.split('-')[0].split('.').map(str => Number(str));
            if (staged_major < 2) {
                dbg.error('Unsupported upgrade, 2.X to 1.X');
                throw new VersionMismatchError('MAJOR_VERSION_CHANGE');
            }
            // calc value of versions to compare
            const staged_ver_val = (staged_major * 10000) + (staged_minor * 100) + staged_patch;
            const current_ver_val = (current_major * 10000) + (current_minor * 100) + current_patch;
            if (staged_ver_val < current_ver_val) {
                dbg.error(`Unsupported upgrade, cannot downgrade. staged version = ${staged_package}, current version = ${pkg.version}`);
                throw new VersionMismatchError('CANNOT_DOWNGRADE');
            }
        });
}

function test_internet_connectivity(phone_home_proxy_address) {
    const options = _.isEmpty(phone_home_proxy_address) ? undefined : {
        proxy: phone_home_proxy_address
    };
    return P.resolve()
        .then(() => phone_home_utils.verify_connection_to_phonehome(options))
        .catch(err => {
            dbg.error('test_internet_connectivity failed', err);
            throw new Error('INTERNET_CONNECTIVITY');
        });
}

function test_local_harddrive_memory() {
    return P.resolve()
        //This logic is performed here on two accounts:
        //Reading the HB from the mongo is possible, but would also require reading the noobaa_sec to identify which is
        //the current server to find it in the shards array. In addition, HB storage status might be over the threshold but
        //actual state is below and the package won't have space to be written
        .then(() => os_utils.read_drives())
        .then(drives => {
            let root = drives.find(drive => drive.mount === '/');
            if (root.storage.free < config.MIN_MEMORY_FOR_UPGRADE) {
                dbg.error(`NOT_ENOUGH_MEMORY_IN_MACHINE MEM_IN_BYTES:${root.free}`);
                throw new Error('LOCAL_HARDDRIVE_MEMORY');
            }
        });

}

function test_package_extraction() {
    return P.resolve()
        .then(() => extract_package())
        .catch(err => {
            dbg.error('extract_package: Failed with', err);
            throw new Error('PACKAGE_EXTRACTION');
        });
}

function new_pre_upgrade() {
    return P.resolve()
        .then(() => extract_new_pre_upgrade_params())
        .then(params => new_pre_upgrade_checkups(params))
        .then(() => packages_upgrade())
        .timeout(20 * 60 * 1000, 'PACKAGE_INSTALLATION_TIMEOUT');
}

function pre_upgrade_checkups(params) {
    dbg.log0('performing pre_upgrade_checkups. extract_package = ', params.extract_package);
    return P.join(
            test_major_version_change(),
            P.resolve(params.extract_package && test_package_extraction())
        )
        .catch(err => {
            dbg.error('failed pre_upgrade_checkups with error', err);
            throw new ExtractionError(err.message);
        });
}

function extract_new_pre_upgrade_params() {
    return P.resolve()
        .then(() => mongo_client.instance().connect())
        .then(() => P.join(
            _get_phone_home_proxy_address(),
            _get_ntp_address()
        ).spread((phone_home_proxy_address, ntp_server) => ({
            ntp_server,
            phone_home_proxy_address
        })))
        .catch(err => {
            dbg.error('extract_new_pre_upgrade_params had errors', err);
            throw new Error('COULD_NOT_EXTRACT_PARAMS');
        });
}

function _get_phone_home_proxy_address() {
    const query = {
        deleted: null
    };
    const reply = {
        phone_home_proxy_address: true
    };
    return P.resolve()
        .then(() => mongo_client.instance().collection('systems').findOne(query, reply))
        .then(response => {
            if (!response) throw new Error('CANNOT_UPGRADE_WITHOUT_SYSTEM');
            return response.phone_home_proxy_address;
        });
}

function _get_ntp_address() {
    return P.resolve()
        .then(() => os_utils.get_ntp());
}

function new_pre_upgrade_checkups(params) {
    return P.join(
        test_internet_connectivity(params.phone_home_proxy_address),
        // TODO: Check the NTP with consideration to the proxy
        test_ntp_timeskew(params.ntp_server),
        test_local_harddrive_memory()
    );
}

function do_yum_update() {
    dbg.log0('fix_security_issues: Called');
    return promise_utils.exec(`cp -fd /etc/localtime /tmp`, {
            ignore_rc: false,
            return_stdout: true,
            trim_stdout: true
        })
        .then(() => promise_utils.exec(`yum clean all`, {
            ignore_rc: false,
            return_stdout: true,
            trim_stdout: true
        }))
        .then(res => {
            dbg.log0('fix_security_issues: yum clean', res);
        })
        .then(() => promise_utils.exec(`yum update -y`, {
            ignore_rc: false,
            return_stdout: true,
            trim_stdout: true
        }))
        .then(res => {
            dbg.log0('fix_security_issues: yum update', res);
        })
        .then(() => promise_utils.exec(`yum clean all`, {
            ignore_rc: false,
            return_stdout: true,
            trim_stdout: true
        }))
        .then(() => {
            dbg.log0(`Updated yum packages`);
        })
        .then(() => promise_utils.exec(`cp -fd /tmp/localtime /etc`, {
            ignore_rc: false,
            return_stdout: true,
            trim_stdout: true
        }))
        .then(() => {
            dbg.log0('fix_security_issues: Success');
        })
        .catch(function(err) {
            dbg.error('fix_security_issues: Failure', err);
            throw err;
        });
}


function packages_upgrade() {
    dbg.log0(`fix SCL issue (centos-release-SCL)`);
    return promise_utils.exec(`yum -y remove centos-release-SCL`, {
            ignore_rc: false,
            return_stdout: true,
            trim_stdout: true
        })
        .then(() => {
            dbg.log0('packages_upgrade: Removed centos-release-SCL');
        })
        .then(() => promise_utils.exec(`cp -f ${EXTRACTION_PATH}/noobaa-core/src/deploy/NVA_build/rsyslog.repo /etc/yum.repos.d/rsyslog.repo`, {
            ignore_rc: false,
            return_stdout: true,
            trim_stdout: true
        }))
        .then(() => promise_utils.exec(`cp -f ${EXTRACTION_PATH}/noobaa-core/src/deploy/NVA_build/RPM-GPG-KEY-Adiscon ${CORE_DIR}/src/deploy/NVA_build/RPM-GPG-KEY-Adiscon`, {
            ignore_rc: false,
            return_stdout: true,
            trim_stdout: true
        }))
        .then(() => promise_utils.exec(`yum -y install centos-release-scl`, {
            ignore_rc: false,
            return_stdout: true,
            trim_stdout: true
        }))
        .then(() => {
            dbg.log0('packages_upgrade: Installed centos-release-scl');
        })
        .then(() => {
            const packages_to_install = [
                'sudo',
                'lsof',
                'wget',
                'curl',
                'ntp',
                'rsyslog',
                'cronie',
                'openssh-server',
                'dialog',
                'expect',
                'nc',
                'tcpdump',
                'iperf',
                'iperf3',
                'python-setuptools',
                'bind-utils',
                'screen',
                'strace',
                'vim'
            ];
            dbg.log0(`install additional packages`);
            return promise_utils.exec(`yum install -y ${packages_to_install.join(' ')}`, {
                    ignore_rc: false,
                    return_stdout: true,
                    trim_stdout: true
                })
                .then(res => {
                    dbg.log0(res);
                });
        })
        .then(do_yum_update)
        .catch(err => {
            dbg.error('packages_upgrade: Failure', err);
            throw new Error('COULD_NOT_INSTALL_PACKAGES');
        });
}

function extract_package() {
    dbg.log0('extract_package: Called');
    // Clean previous extracted package
    return fs_utils.create_fresh_path(EXTRACTION_PATH)
        .then(() => {
            dbg.log0(`extract_package: Path ${EXTRACTION_PATH} was created`);
        })
        .then(() => promise_utils.exec(`cp ${TMP_PATH}/${PACKAGE_FILE_NAME} ${EXTRACTION_PATH}`, {
            ignore_rc: false,
            return_stdout: true,
            trim_stdout: true
        }))
        .then(function() {
            return promise_utils.exec(`cd ${EXTRACTION_PATH}/;tar --same-owner -xzvf ${EXTRACTION_PATH}/${PACKAGE_FILE_NAME} >& /dev/null`, {
                    ignore_rc: false,
                    return_stdout: true,
                    trim_stdout: true
                })
                .then(res => {
                    dbg.log0(`extract_package: ${EXTRACTION_PATH}/${PACKAGE_FILE_NAME} was extracted`, res);
                })
                .catch(function(err) {
                    dbg.error(`Corrupted package file, could not open`, err);
                    return fs_utils.folder_delete(EXTRACTION_PATH)
                        .finally(() => {
                            throw new Error(`extract_package: Corrupted package file, could not open`);
                        });
                });
        })
        .then(() => {
            dbg.log0('extract_package: Success');
        })
        .catch(err => {
            dbg.error('extract_package: Failure', err);
            throw err;
        });
}

if (require.main === module) {
    if (argv.new_pre_upgrade) {
        return new_pre_upgrade()
            .then(() => {
                dbg.log0('new_pre_upgrade: SUCCESS');
                process.exit(0);
            })
            .catch(err => {
                dbg.error('new_pre_upgrade: FAILED:', err);
                // This is done because the new spawn only knowns the new errors
                return fs.writeFileAsync(ERRORS_PATH, JSON.stringify({
                        message: (ERROR_MAPPING[err.message] || ERROR_MAPPING.UNKNOWN)
                    }))
                    .catch(error => {
                        dbg.error('new_pre_upgrade: failed to write error file', error);
                    })
                    .finally(() => process.exit(1));
            });
    }
}

//Exports
exports.pre_upgrade = pre_upgrade;
exports.do_upgrade = do_upgrade;
