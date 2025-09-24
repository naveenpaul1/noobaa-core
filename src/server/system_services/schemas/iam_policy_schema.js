/* Copyright (C) 2016 NooBaa */
'use strict';


module.exports = {
    $id: 'iam_policy_schema',
    type: 'object',
    required: [
        '_id',
        'name',
        'policy_type',
        'iam_policy'
    ],
    properties: {
        // identity
        _id: { objectid: true },
        deleted: { date: true },
        name: {type: 'string'},
        policy_type: {
            type: 'string',
            enum: ['INLINE', 'MANAGED']
        },
        iam_policy: {
            $ref: 'common_api#/definitions/bucket_policy',
        },
    }
};
