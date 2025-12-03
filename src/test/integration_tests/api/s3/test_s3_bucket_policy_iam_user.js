/* Copyright (C) 2016 NooBaa */
/* eslint max-lines-per-function: ['error', 650] */
/* eslint max-lines: ["error", 2500] */
'use strict';

// setup coretest first to prepare the env
const { require_coretest, TMP_PATH, generate_iam_client, is_nc_coretest } = require('../../../system_tests/test_utils');
const coretest = require_coretest();
const { rpc_client, EMAIL, POOL_LIST } = coretest;
coretest.setup({ pools_to_create: process.env.NC_CORETEST ? undefined : [POOL_LIST[1]] });
const path = require('path');
const fs_utils = require('../../../../util/fs_utils');

const { S3 } = require('@aws-sdk/client-s3');
const { NodeHttpHandler } = require("@smithy/node-http-handler");
const http = require('http');
const mocha = require('mocha');
const assert = require('assert');
const config = require('../../../../../config');

async function assert_throws_async(promise, expected_message = 'Access Denied') {
    try {
        await promise;
        assert.fail('Test was suppose to fail on ' + expected_message);
    } catch (err) {
        if (err.message !== expected_message) {
            throw err;
        }
    }
}

const { CreateUserCommand, CreateAccessKeyCommand, PutUserPolicyCommand } = require('@aws-sdk/client-iam');

const BKT = 'iam-bucket-policy-ops';
const BKT_B = 'iam-bucket-policy-ops-1';
const BKT_C = 'iam-bucket-policy-ops-2';

const policy_name = 'AllAccessPolicy';
const iam_user_inline_policy_document = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}';

const KEY = 'file1.txt';
const user_a = 'alice';
const user_b = 'bob';
//const user_c = 'carter';
const BODY = "Some data for the file... bla bla bla... ";
let s3_b;
let s3_owner;

let s3_user_a;
let s3_user_b;

let user_a_arn;

// the account creation details (in NC we want to use them)
let user_a_account_details;
let user_b_account_details;

let user_a_id;

let admin_info;


let iam_account_a;
let iam_account_b;

let iam_user_a_s3_creds;
let iam_user_b_s3_creds;

async function setup() {
    const self = this; // eslint-disable-line no-invalid-this
    self.timeout(60000);
    const s3_creds = {
        endpoint: coretest.get_http_address(),
        forcePathStyle: true,
        region: config.DEFAULT_REGION,
        requestHandler: new NodeHttpHandler({
            httpAgent: new http.Agent({ keepAlive: false })
        }),
    };
    const nsr = 's3_bucket_policy_nsr';
    const tmp_fs_root = path.join(TMP_PATH, 'test_s3_bucket_policy');

    if (process.env.NC_CORETEST) {
        await fs_utils.create_fresh_path(tmp_fs_root, 0o777);
    }
    const account = {
        has_login: false,
        s3_access: true,
        default_resource: process.env.NC_CORETEST ? nsr : POOL_LIST[1].name
    };
    if (process.env.NC_CORETEST) {
        account.nsfs_account_config = {
            uid: process.getuid(),
            gid: process.getgid(),
            new_buckets_path: tmp_fs_root
        };
    }
    admin_info = (await rpc_client.account.read_account({
        email: EMAIL,
    }));
    const admin_keys = admin_info.access_keys;
    account.name = user_a;
    account.email = user_a;
    user_a_account_details = await rpc_client.account.create_account(account);
    console.log('user_a_account_details', user_a_account_details);
    const user_a_keys = user_a_account_details.access_keys;
    account.name = user_b;
    account.email = user_b;
    user_b_account_details = await rpc_client.account.create_account(account);
    console.log('user_b_account_details', user_b_account_details);
    const user_b_keys = user_b_account_details.access_keys;
    s3_creds.credentials = {
        accessKeyId: user_b_keys[0].access_key.unwrap(),
        secretAccessKey: user_b_keys[0].secret_key.unwrap(),
    };
    s3_b = new S3(s3_creds);
    await s3_b.createBucket({ Bucket: BKT_B });
    s3_creds.credentials = {
        accessKeyId: admin_keys[0].access_key.unwrap(),
        secretAccessKey: admin_keys[0].secret_key.unwrap(),
    };
    const coretest_endpoint_iam = coretest.get_https_address_iam();
    iam_account_a = generate_iam_client(user_a_keys[0].access_key.unwrap(), user_a_keys[0].secret_key.unwrap(), coretest_endpoint_iam);
    iam_account_b = generate_iam_client(user_b_keys[0].access_key.unwrap(), user_b_keys[0].secret_key.unwrap(), coretest_endpoint_iam);

    s3_owner = new S3(s3_creds);
    await s3_owner.createBucket({ Bucket: BKT });
    await s3_owner.createBucket({ Bucket: BKT_C });

    iam_user_a_s3_creds = {
        endpoint: coretest.get_http_address(),
        forcePathStyle: true,
        region: config.DEFAULT_REGION,
        requestHandler: new NodeHttpHandler({
            httpAgent: new http.Agent({ keepAlive: false })
        }),
    };
    iam_user_b_s3_creds = {
        endpoint: coretest.get_http_address(),
        forcePathStyle: true,
        region: config.DEFAULT_REGION,
        requestHandler: new NodeHttpHandler({
            httpAgent: new http.Agent({ keepAlive: false })
        }),
    };

}

mocha.describe('IAM S3_bucket_policy', function() {
    mocha.before(setup);
    mocha.after(async function() {
        await s3_owner.deleteBucket({
            Bucket: BKT,
        });
    });

    mocha.it('IAM User access bucket with Bucket policy', async function() {
        if (is_nc_coretest) this.skip(); // eslint-disable-line no-invalid-this
        const input = {
            UserName: user_a
        };
        // 1. Create IAM user account
        const command = new CreateUserCommand(input);
        const response = await iam_account_a.send(command);
        _check_status_code_ok(response);
        assert.equal(response.User.UserName, user_a);
        user_a_arn = response.User.Arn;
        user_a_id = response.User.UserId;
        // 2. Create bucket policy with that IAM user and add to bucket
        const s3_policy = {
            Version: '2012-10-17',
            Statement: [
                {
                    Action: ['s3:PutObject'],
                    Effect: 'Allow',
                    Principal: { AWS: [user_a_arn] },
                    Resource: [`arn:aws:s3:::${BKT}/*`],
                }
            ]};

        await s3_owner.putBucketPolicy({
            Bucket: BKT,
            Policy: JSON.stringify(s3_policy)
        });
        const res_get_bucket_policy = await s3_owner.getBucketPolicy({
            Bucket: BKT,
        });
        assert.equal(res_get_bucket_policy.$metadata.httpStatusCode, 200);
        // 3. Create access and secret key for the IAM user
        const access_command = new CreateAccessKeyCommand(input);
        const access_response = await iam_account_a.send(access_command);

        const access_key_id = access_response.AccessKey.AccessKeyId;
        const secret_key = access_response.AccessKey.SecretAccessKey;
        assert(access_key_id !== undefined);

        // 4. Add inline policy to account, without inline policy S3 access will fail.
        const inline_input = {
            UserName: user_a,
            PolicyName: policy_name,
            PolicyDocument: iam_user_inline_policy_document
        };
        const inline_command = new PutUserPolicyCommand(inline_input);
        const inline_response = await iam_account_a.send(inline_command);
        _check_status_code_ok(inline_response);

        // 5. Try to put object to bucket with IAM user s3 client, Should not fail
        iam_user_a_s3_creds.credentials = {
            accessKeyId: access_key_id,
            secretAccessKey: secret_key,
        };
        s3_user_a = new S3(iam_user_a_s3_creds);
        const res_put_object = await s3_user_a.putObject({
            Body: BODY,
            Bucket: BKT,
            Key: KEY,
        });
        assert.equal(res_put_object.$metadata.httpStatusCode, 200);
        await s3_owner.deleteObject({
            Bucket: BKT,
            Key: KEY
        });
    });

    mocha.it('IAM User access bucket that its owner account owns', async function() {
        if (is_nc_coretest) this.skip(); // eslint-disable-line no-invalid-this
        const input = {
            UserName: user_b
        };
        // 1. Create IAM user account
        const command = new CreateUserCommand(input);
        const response_b = await iam_account_b.send(command);
        _check_status_code_ok(response_b);
        assert.equal(response_b.User.UserName, user_b);
        // 2. Create access and secret key for the IAM user
        const access_command = new CreateAccessKeyCommand(input);
        const access_response = await iam_account_b.send(access_command);

        const access_key_id = access_response.AccessKey.AccessKeyId;
        const secret_key = access_response.AccessKey.SecretAccessKey;
        assert(access_key_id !== undefined);

        // 3. Add inline policy to account, without inline policy S3 access will fail.
        const inline_input = {
            UserName: user_b,
            PolicyName: policy_name,
            PolicyDocument: iam_user_inline_policy_document
        };
        const inline_command = new PutUserPolicyCommand(inline_input);
        const inline_response = await iam_account_b.send(inline_command);
        _check_status_code_ok(inline_response);

        // 5. Try to put object to bucket with IAM user s3 client, Should not fail
        iam_user_b_s3_creds.credentials = {
            accessKeyId: access_key_id,
            secretAccessKey: secret_key,
        };
        s3_user_b = new S3(iam_user_b_s3_creds);
        const res_put_object = await s3_user_b.putObject({
            Body: BODY,
            Bucket: BKT_B,
            Key: KEY,
        });
        assert.equal(res_put_object.$metadata.httpStatusCode, 200);
        await s3_b.deleteObject({
            Bucket: BKT_B,
            Key: KEY
        });
    });

    mocha.it('Should fail: IAM user\'s owner account owns the bucket with bucket policy', async function() {
        if (is_nc_coretest) this.skip(); // eslint-disable-line no-invalid-this
        const s3_policy = {
            Version: '2012-10-17',
            Statement: [
                {
                    Action: ['s3:PutObject'],
                    Effect: 'Allow',
                    Principal: { AWS: [user_a_arn] },
                    Resource: [`arn:aws:s3:::${BKT_B}/*`],
                }
            ]};

        await s3_b.putBucketPolicy({
            Bucket: BKT_B,
            Policy: JSON.stringify(s3_policy)
        });
        const res_get_bucket_policy = await s3_b.getBucketPolicy({
            Bucket: BKT_B,
        });
        assert.equal(res_get_bucket_policy.$metadata.httpStatusCode, 200);

        s3_user_b = new S3(iam_user_b_s3_creds);
        // If there is bucket policy, owner account bucket access is denaied for user.
        await assert_throws_async(s3_user_b.putObject({
            Body: BODY,
            Bucket: BKT_B,
            Key: KEY,
        }));
    });

    mocha.it('Should fail : Bucket policy with IAM User ID not supported', async function() {
        if (is_nc_coretest) this.skip(); // eslint-disable-line no-invalid-this
        const s3_policy = {
            Version: '2012-10-17',
            Statement: [
                {
                    Action: ['s3:PutObject'],
                    Effect: 'Allow',
                    Principal: { AWS: [user_a_id] },
                    Resource: [`arn:aws:s3:::${BKT}/*`],
                }
            ]};
        await assert_throws_async(s3_owner.putBucketPolicy({
            Bucket: BKT,
            Policy: JSON.stringify(s3_policy)
        }));
    });


    // NC test cases

});

/**
 * _check_status_code_ok is an helper function to check that we got an response from the server
 * @param {{ $metadata: { httpStatusCode: number; }; }} response
 */
function _check_status_code_ok(response) {
    assert.equal(response.$metadata.httpStatusCode, 200);
}
