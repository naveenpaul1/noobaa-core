/* Copyright (C) 2024 NooBaa */
'use strict';

const _ = require('lodash');
const SensitiveString = require('../util/sensitive_string');
const account_util = require('./../util/account_util');
const iam_utils = require('../endpoint/iam/iam_utils');
const system_store = require('..//server/system_services/system_store').get_instance();
const { IAM_DEFAULT_PATH } = require('../endpoint/iam/iam_constants');


////////////////////
// MOCK VARIABLES //
////////////////////
/* mock variables (until we implement the actual code), based on the example in AWS IAM API docs*/

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

    async create_user(params, account_sdk) {
        const requesting_account = account_sdk.requesting_account;
        //console.log("CREATE IAM USER ======>>>>@@@@@", requesting_account)
        //console.log("CREATE IAM PARAMS ======>>>>!!!!", params);
        const root_account = _.find(system_store.data.accounts, account => account.name.unwrap() === requesting_account.name.unwrap());
        //console.log("ROOTTT======>>>>", root_account)

        const iam_arn = iam_utils.create_arn_for_user('qwerty123', params.username, params.iam_path);
        const req = {
            rpc_params: {
                name: new SensitiveString(params.username),
                email: new SensitiveString(params.username),
                has_login: false,
                s3_access: true,
                allow_bucket_creation: true,
                owner: root_account._id,
                is_iam: true,
                iam_arn: iam_arn,
                role: 'iam_user',
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

    async get_user(params) {
        console.log("Implemention pending");
    }

    async update_user(params) {
        console.log("Implemention pending");
    }

    async delete_user(params) {
        console.log("Implemention pending");
    }

    async list_users(params) {
        console.log("Implemention pending");
    }

    async create_access_key(params) {
        console.log("Implemention pending");
    }

    async get_access_key_last_used(params) {
        console.log("Implemention pending");
    }

    async update_access_key(params) {
        console.log("Implemention pending");
    }

    async delete_access_key(params) {
        console.log("Implemention pending");
    }

    async list_access_keys(params) {
        console.log("Implemention pending");
    }
}

// EXPORTS
module.exports = AccountSpaceNB;
