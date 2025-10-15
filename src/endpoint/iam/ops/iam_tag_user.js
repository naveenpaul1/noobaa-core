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
async function tag_user(req, res) {

    let tags;

    try {
        // TODO: Get tag key value pair
        // { action: 'TagUser', version: '2010-05-08', user_name: 'Bob', 
        //  tags_member_1_key: 'Department', tags_member_1_value: 'Accounting', 
        //  tags_member_2_key: 'Department2', tags_member_2_value: 'Accounting2' 
        // }
        tags = JSON.parse(JSON.stringify(req.body.tags));
    } catch (error) {
        console.error('tag_user: Invalid JSON provided', error);
        throw new IamError(IamError.InvalidInput);
    }
    const params = {
        username: req.body.user_name,
        tags: tags,
    };

    dbg.log1('To check that we have the user we will run the IAM TAG USER', params);
    iam_utils.validate_params(iam_constants.IAM_ACTIONS.TAG_USER, params);
    await req.account_sdk.tag_user(params);

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
    handler: tag_user,
    body: {
        type: CONTENT_TYPE_APP_FORM_URLENCODED,
    },
    reply: {
        type: 'xml',
    },
};
