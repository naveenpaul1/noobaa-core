/* Copyright (C) 2024 NooBaa */
'use strict';

const _ = require('lodash');
const SensitiveString = require('../util/sensitive_string');
const account_util = require('./../util/account_util');
const iam_utils = require('../endpoint/iam/iam_utils');
const system_store = require('..//server/system_services/system_store').get_instance();
const { IAM_ACTIONS, IAM_DEFAULT_PATH, ACCESS_KEY_STATUS_ENUM, IAM_SPLIT_CHARACTERS } = require('../endpoint/iam/iam_constants');

/* 
    TODO: DISCUSS: 
    1. IAM API only for account created using IAM API and OBC accounts not from admin, support, 
       operator and account created using noobaa.
    2. 
*/

/**
 * @implements {nb.AccountSpace}
 */
class AccountSpaceNB {
    /**
     * @param {{
     *      rpc_client: nb.APIClient;
     *      internal_rpc_client: nb.APIClient;
     *      stats?: import('./endpoint_stats_collector').EndpointStatsCollector;
     * }} params
     */
    constructor({ rpc_client, internal_rpc_client, stats }) {
        this.rpc_client = rpc_client;
        this.internal_rpc_client = internal_rpc_client;
        this.stats = stats;
    }

    //////////////////////
    // ACCOUNT METHODS  //
    //////////////////////

    async create_user(params, account_sdk) {

        const action = IAM_ACTIONS.CREATE_USER;
        const requesting_account = account_sdk.requesting_account;
        const root_account = _.find(system_store.data.accounts, account => account.name.unwrap() === requesting_account.name.unwrap());
        account_util._check_if_requesting_account_is_root_account(action, requesting_account,
                { username: params.username, iam_path: params.iam_path });
        await account_util._check_username_already_exists(action, params, requesting_account);
        const iam_arn = iam_utils.create_arn_for_user(root_account._id.toString(), params.username, params.iam_path);
        const account_name = new SensitiveString(`${params.username}:${requesting_account.name.unwrap()}`);
        const req = {
            rpc_params: {
                name: account_name,
                email: account_name,
                has_login: false,
                s3_access: true,
                allow_bucket_creation: true,
                owner: root_account._id.toString(),
                is_iam: true,
                iam_arn: iam_arn,
                role: 'iam_user',
                // TODO: default_resource remove
                default_resource: 'noobaa-default-backing-store',
            },
            account: requesting_account,
        };
        const iam_account = await account_util.create_account(req);

        return {
                iam_path: requesting_account.iam_path || IAM_DEFAULT_PATH,
                username: params.username,
                user_id: iam_account.id,
                arn: iam_arn,
                create_date: iam_account.creation_date,
            };
    }

    async get_user(params, account_sdk) {
        const action = IAM_ACTIONS.GET_USER;
        const requesting_account = account_sdk.requesting_account;
        const account_name = new SensitiveString(`${params.username}:${requesting_account.name.unwrap()}`);
        const account = system_store.get_account_by_email(account_name);
        account_util._check_if_requesting_account_is_root_account(action, requesting_account,
                { username: params.username, iam_path: params.iam_path });
        await account_util._check_if_account_exists(action, params.username, params, requesting_account);
        account_util._check_if_requested_account_is_root_account_or_IAM_user(action, requesting_account, account);
        const root_account = system_store.get_account_by_email(requesting_account.email);
        account_util._check_if_requested_is_owned_by_root_account(action, root_account, account);
        const reply = {
            user_id: account._id.toString(),
            iam_path: account.iam_path || IAM_DEFAULT_PATH,
            username: account.name.unwrap(),
            arn: account.iam_arn,
            // TODO: Dates missing : GAP
            create_date: new Date(),
            password_last_used: new Date(),
        };
        return reply;
    }

    async update_user(params, account_sdk) {
        console.log("Implemention pending");
    }

    async delete_user(params, account_sdk) {

        const action = IAM_ACTIONS.DELETE_USER;
        // GAP - we do not have the user iam_path at this point (error message)
        const requesting_account = account_sdk.requesting_account;
        const account_name = new SensitiveString(`${params.username}:${requesting_account.name.unwrap()}`);
        const account_to_delete = system_store.get_account_by_email(account_name);
        account_util._check_if_requesting_account_is_root_account(action, requesting_account, { username: params.username });
        await account_util._check_if_account_exists(action, params.username, params, requesting_account);
        account_util._check_if_requested_account_is_root_account_or_IAM_user(action, requesting_account, account_to_delete);
        const root_account = system_store.get_account_by_email(requesting_account.email);
        account_util._check_if_requested_is_owned_by_root_account(action, root_account, account_to_delete);
        // TODO: DELETE INLINE POLICY : Manually
        // TODO: DELETE ACCESS KEY : manually
        account_util._check_if_user_does_not_have_inline_policy_before_deletion(action, account_to_delete);
        account_util._check_if_user_does_not_have_access_keys_before_deletion(action, account_to_delete);
        const req = {
            system: system_store.data.systems[0],
            account: String(root_account._id),
        };
        return account_util.delete_user(req, account_to_delete);
        // TODO : clean account cache

    }

    async list_users(params, account_sdk) {
        console.log("Implemention pending");
        const action = IAM_ACTIONS.LIST_USERS;
        const requesting_account = account_sdk.requesting_account;
        account_util._check_if_requesting_account_is_root_account(action, requesting_account, { });
        const is_truncated = false; // GAP - no pagination at this point

        const root_name = requesting_account.name.unwrap();
        const requesting_account_iam_users = _.filter(system_store.data.accounts, function(acc) {
            if (!acc.name.unwrap().includes(IAM_SPLIT_CHARACTERS)) {
                return false;
            }
            return acc.name.unwrap().split(IAM_SPLIT_CHARACTERS)[1] === root_name;
        });
        let members = _.map(requesting_account_iam_users, function(iam_user) {
            const member = {
                user_id: iam_user._id.toString(),
                iam_path: iam_user.iam_path || IAM_DEFAULT_PATH,
                username: iam_user.name.unwrap().split(IAM_SPLIT_CHARACTERS)[0],
                arn: iam_user.iam_arn,
                create_date: iam_user.creation_date,
                password_last_used: Date.now(), // GAP
            };
            return member;
        });
        members = members.sort((a, b) => a.username.localeCompare(b.username));
        return { members, is_truncated };
    }

    /////////////////////////////////
    // ACCOUNT ACCESS KEY METHODS  //
    /////////////////////////////////

    async create_access_key(params, account_sdk) {
        // const action = IAM_ACTIONS.CREATE_ACCESS_KEY;
        const account_name = new SensitiveString(`${params.username}:${account_sdk.requesting_account.name.unwrap()}`);
        const account = system_store.get_account_by_email(new SensitiveString(account_name));
        const requesting_account = system_store.get_account_by_email(new SensitiveString(account_sdk.requesting_account.email));
        // TODO : this._check_number_of_access_key_array(action, requested_account);
        // TODO: _check_if_requesting_account_is_root_account
        // TODO: ACTIVE FLAG missing    
        const req = {
            rpc_params: {
                email: new SensitiveString(account_name),
                is_iam: true,
            },
            account: requesting_account,
        };
        const iam_access_key = await account_util.generate_account_keys(req);

        return {
            username: account.name,
            access_key: iam_access_key.access_key.unwrap(),
            create_date: new Date(),
            status: ACCESS_KEY_STATUS_ENUM.ACTIVE,
            secret_key: iam_access_key.secret_key.unwrap(),
        };
    }

    async get_access_key_last_used(params) {
        console.log("Implemention pending");
    }

    async update_access_key(params) {
        console.log("Implemention pending");
    }

    async delete_access_key(params) {
        // TODO: Deactive access key first
        console.log("Implemention pending");
    }

    async list_access_keys(params) {
        console.log("Implemention pending");
    }

    ////////////////////
    // POLICY METHODS //
    ////////////////////

    async put_user_policy(params, account_sdk) {
        // TODO : Invlidate cache
        // TODO: Only S3 policy
        // AWS Access not given without policy. Disscus
        const account_name = new SensitiveString(`${params.username}:${account_sdk.requesting_account.name.unwrap()}`);
        const account = system_store.get_account_by_email(new SensitiveString(account_name));
         const req = {
            rpc_params: {
                account_id: account._id,
                policy_type: 'INLINE',
                s3_policy: JSON.parse(params.policy_document),
                policy_name: params.policy_name,
            },
        };
        return account_util.put_user_policy(req);
    }
}

// EXPORTS
module.exports = AccountSpaceNB;
