/* Copyright (C) 2016 NooBaa */
'use strict';

const _ = require('lodash');
const Dispatcher = require('../server/notifications/dispatcher');

const dbg = require('../util/debug_module')(__filename);
const { RpcError } = require('../rpc');
const SensitiveString = require('../util/sensitive_string');
const cloud_utils = require('../util/cloud_utils');
const auth_server = require('..//server/common_services/auth_server');
const system_store = require('..//server/system_services/system_store').get_instance();
const pool_server = require('../server/system_services/pool_server');
const { OP_NAME_TO_ACTION } = require('../endpoint/sts/sts_rest');


const demo_access_keys = Object.freeze({
    access_key: new SensitiveString('123'),
    secret_key: new SensitiveString('abc')
});
/**
 *
 * CREATE_ACCOUNT
 *
 */
async function create_account(req) {
    //console.log("create_account  =====>>", req.rpc_params)
    const account = {
        _id: (
            req.rpc_params.new_system_parameters ?
            system_store.parse_system_store_id(req.rpc_params.new_system_parameters.account_id) :
            system_store.new_system_store_id()
        ),
        name: req.rpc_params.name,
        email: req.rpc_params.email,
        has_login: req.rpc_params.has_login,
        is_external: req.rpc_params.is_external,
        nsfs_account_config: req.rpc_params.nsfs_account_config,
        force_md5_etag: req.rpc_params.force_md5_etag
    };

    if (!req.system) {
        req.system = system_store.data.systems[0];
    }

    const { roles: account_roles = ['admin'] } = req.rpc_params;

    validate_create_account_permissions(req);
    validate_create_account_params(req);

    if (account.name.unwrap() === 'demo' && account.email.unwrap() === 'demo@noobaa.com') {
        account.access_keys = [demo_access_keys];
    } else {
        const access_keys = req.rpc_params.access_keys || [cloud_utils.generate_access_keys()];
        if (!access_keys.length) throw new RpcError('FORBIDDEN', 'cannot create account without access_keys');
        account.access_keys = access_keys;
    }

    const sys_id = req.rpc_params.new_system_parameters ?
        system_store.parse_system_store_id(req.rpc_params.new_system_parameters.new_system_id) :
        req.system._id;

    if (req.rpc_params.s3_access) {
        if (req.rpc_params.new_system_parameters) {
            account.default_resource = system_store.parse_system_store_id(req.rpc_params.new_system_parameters.default_resource);
            account.allow_bucket_creation = true;
        } else {
            // Default pool resource is backingstores
            const resource = req.rpc_params.default_resource ?
            req.system.pools_by_name[req.rpc_params.default_resource] ||
                (req.system.namespace_resources_by_name && req.system.namespace_resources_by_name[req.rpc_params.default_resource]) :
                pool_server.get_default_pool(req.system);
            if (!resource) throw new RpcError('BAD_REQUEST', 'default resource doesn\'t exist');
            if (resource.nsfs_config && resource.nsfs_config.fs_root_path && !req.rpc_params.nsfs_account_config) {
                throw new RpcError('Invalid account configuration - must specify nsfs_account_config when default resource is a namespace resource');
            }
            account.default_resource = resource._id;
            account.allow_bucket_creation = _.isUndefined(req.rpc_params.allow_bucket_creation) ?
                true : req.rpc_params.allow_bucket_creation;

            const bucket_claim_owner = req.rpc_params.bucket_claim_owner;
            if (bucket_claim_owner) {
                const creator_roles = req.account.roles_by_system[req.system._id];
                if (creator_roles.includes('operator')) { // Not allowed to create claim owner outside of the operator
                    account.bucket_claim_owner = req.system.buckets_by_name[bucket_claim_owner.unwrap()]._id;
                } else {
                    dbg.warn('None operator user was trying to set a bucket-claim-owner for account', req.account);
                }
            }
        }
    }

    const roles = account_roles.map(role => ({
        _id: system_store.new_system_store_id(),
        account: account._id,
        system: sys_id,
        role
    }));

    // Suppress audit entry for creation of operator account.
    if (!account_roles.includes('operator')) {
        Dispatcher.instance().activity({
            event: 'account.create',
            level: 'info',
            system: (req.system && req.system._id) || sys_id,
            actor: req.account && req.account._id,
            account: account._id,
            desc: `${account.email.unwrap()} was created ` + (req.account ? `by ${req.account.email.unwrap()}` : ``),
        });
    }
    const account_mkey = system_store.master_key_manager.new_master_key({
        description: `master key of ${account._id} account`,
        cipher_type: system_store.data.systems[0].master_key_id.cipher_type,
        master_key_id: system_store.data.systems[0].master_key_id._id
    });
    account.master_key_id = account_mkey._id;
    const decrypted_access_keys = _.cloneDeep(account.access_keys);
    account.access_keys[0] = {
        access_key: account.access_keys[0].access_key,
        secret_key: system_store.master_key_manager.encrypt_sensitive_string_with_master_key_id(
            account.access_keys[0].secret_key, account_mkey._id)
    };

    if (req.rpc_params.role_config) {
        validate_assume_role_policy(req.rpc_params.role_config.assume_role_policy);
        account.role_config = req.rpc_params.role_config;
    }
    if (req.rpc_params.is_iam) {
        account.owner = req.rpc_params.owner;
        account.is_iam = req.rpc_params.is_iam;
        account.iam_arn = req.rpc_params.iam_arn;
    }

    await system_store.make_changes({
        insert: {
            accounts: [account],
            roles,
            master_keys: [account_mkey]
        }
    });

    const created_account = system_store.data.get_by_id(account._id);
    const auth = {
        account_id: created_account._id
    };
    // since we created the first system for this account
    // we expect just one system, but use _.each to get it from the map
    const current_system = (req.system && req.system._id) || sys_id;
    _.each(created_account.roles_by_system, (sys_roles, system_id) => {
        //we cannot assume only one system.
        if (current_system.toString() === system_id) {
            auth.system_id = system_id;
            auth.role = sys_roles[0];
        }
    });
    return {
        token: auth_server.make_auth_token(auth),
        access_keys: decrypted_access_keys,
        id: req.rpc_params.is_iam ? created_account._id : undefined,
        create_date: req.rpc_params.is_iam ? new Date(created_account.last_update) : undefined,
    };
}

function validate_create_account_permissions(req) {
    const account = req.account;
    //For new system creation, nothing to be checked
    if (req.rpc_params.new_system_parameters) return;

    //Only allow support, admin/operator roles and UI login enabled accounts to create new accounts
    if (!account.is_support &&
        !account.has_login &&
        !(account.roles_by_system[req.system._id].some(
            role => role === 'admin' || role === 'operator'
        ))) {
        throw new RpcError('UNAUTHORIZED', 'Cannot create new account');
    }
}

function validate_create_account_params(req) {
    // find none-internal pools
    const has_non_internal_resources = (req.system && req.system.pools_by_name) ?
        Object.values(req.system.pools_by_name).some(p => !p.is_default_pool) :
        false;

    if (req.rpc_params.name.unwrap() !== req.rpc_params.name.unwrap().trim()) {
        throw new RpcError('BAD_REQUEST', 'system name must not contain leading or trailing spaces');
    }

    if (system_store.get_account_by_email(req.rpc_params.email)) {
        throw new RpcError('BAD_REQUEST', 'email address already registered');
    }

    if (req.rpc_params.s3_access) {
        if (!req.rpc_params.new_system_parameters) {
            if (req.system.pools_by_name === 0) {
                throw new RpcError('No resources in the system - Can\'t create accounts');
            }

            if (req.rpc_params.allow_bucket_creation && !req.rpc_params.default_resource) { //default resource needed only if new bucket can be created
                if (has_non_internal_resources) { // has resources which is not internal - must supply resource
                    throw new RpcError('BAD_REQUEST', 'Enabling S3 requires providing default_resource');
                }
            }
        }

        if (req.rpc_params.new_system_parameters) {
            if (!req.rpc_params.new_system_parameters.default_resource) {
                throw new RpcError(
                    'BAD_REQUEST',
                    'Creating new system with enabled S3 access for owner requires providing default_resource'
                );
            }
        }
    }

    if (req.rpc_params.has_login) {
        if (!req.rpc_params.password) {
            throw new RpcError('BAD_REQUEST', 'Password is missing');
        }

        // Verify that account with login access have full s3 access permissions.
        const { default_resource } = req.rpc_params.new_system_parameters || req.rpc_params;
        const allow_bucket_creation = req.rpc_params.new_system_parameters ?
            true :
            req.rpc_params.allow_bucket_creation;

        if (
            !req.rpc_params.s3_access ||
            (has_non_internal_resources && !default_resource) ||
            !allow_bucket_creation
        ) {
            throw new RpcError('BAD_REQUEST', 'Accounts with login access must have full s3 access permissions');
        }

    } else if (req.rpc_params.password) {
        throw new RpcError('BAD_REQUEST', 'Password should not be sent');
    }
}

function validate_assume_role_policy(policy) {
    const all_op_names = Object.values(OP_NAME_TO_ACTION);
    for (const statement of policy.statement) {
        for (const principal of statement.principal) {
            if (principal.unwrap() !== '*') {
                const account = system_store.get_account_by_email(principal);
                if (!account) {
                    throw new RpcError('MALFORMED_POLICY', 'Invalid principal in policy', { detail: principal });
                }
            }
        }
        for (const action of statement.action) {
            if (action !== 'sts:*' && !all_op_names.includes(action)) {
                throw new RpcError('MALFORMED_POLICY', 'Policy has invalid action', { detail: action });
            }
        }
    }
}

exports.create_account = create_account;
