/* Copyright (C) 2024 NooBaa */
'use strict';

const dbg = require('../../../util/debug_module')(__filename);
const IamError = require('../iam_errors').IamError;
const iam_utils = require('../iam_utils');
const iam_constants = require('../iam_constants');
const { CONTENT_TYPE_APP_FORM_URLENCODED } = require('../../../util/http_utils');

/**
 * https://docs.aws.amazon.com/cli/latest/reference/iam/put-user-policy.html
 */
async function put_user_policy(req, res) {
    let iam_policy;
    try {
        iam_policy = JSON.parse(JSON.stringify(req.body.policy_document));
    } catch (error) {
        console.error('put_bucket_policy: Invalid JSON provided', error);
        throw new IamError(IamError.InvalidInput);
    }
    const params = {
        username: req.body.user_name,
        policy_name: req.body.policy_name,
        policy_document: iam_policy
    };
    iam_utils.validate_params(iam_constants.IAM_ACTIONS.PUT_USER_POLICY, params);
    dbg.log1('IAM PUT USER POLICY', params);
    const reply = await req.account_sdk.put_user_policy(params);
    dbg.log2('put_user_policy reply', reply);

    return {
        DeleteAccessKeyResponse: {
            ResponseMetadata: {
                RequestId: req.request_id,
            }
        }
    };
}

module.exports = {
    handler: put_user_policy,
    body: {
        type: CONTENT_TYPE_APP_FORM_URLENCODED,
    },
    reply: {
        type: 'xml',
    },
};
