/* Copyright (C) 2024 NooBaa */
'use strict';

const dbg = require('../../../util/debug_module')(__filename);
const iam_utils = require('../iam_utils');
const iam_constants = require('../iam_constants');
const IamError = require('../iam_errors').IamError;
const { CONTENT_TYPE_APP_FORM_URLENCODED } = require('../../../util/http_utils');

/**
 * https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListUserTags.html
 */
async function untag_user(req, res) {

    let tag_keys;
    try {
        tag_keys = JSON.stringify(req.body.tag_keys).split(' ');
    } catch (error) {
        console.error('tag_user: Invalid JSON provided', error);
        throw new IamError(IamError.InvalidInput);
    }
    const params = {
        username: req.body.user_name,
        tag_keys: tag_keys,
    };

    dbg.log1('To check that we have the user we will run the IAM TAG USER', params);
    iam_utils.validate_params(iam_constants.IAM_ACTIONS.UNTAG_USER, params);
    await req.account_sdk.untag_user(params);

    dbg.log1('IAM LIST USER TAGS (returns empty list on every request)', params);

    return {
        TagUserResponse: {
            ResponseMetadata: {
                RequestId: req.request_id,
            }
        },
    };
}

module.exports = {
    handler: untag_user,
    body: {
        type: CONTENT_TYPE_APP_FORM_URLENCODED,
    },
    reply: {
        type: 'xml',
    },
};
