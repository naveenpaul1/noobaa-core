/* Copyright (C) 2016 NooBaa */
'use strict';


module.exports = {
    $id: 'iam_policy_schema',
    type: 'object',
    required: [
        '_id',
        'name',
        'type',
        's3_policy'
    ],
    properties: {
        // identity
        _id: { objectid: true },
        deleted: { date: true },
        name: {type: 'string'},
        type: {
            type: 'string',
            enum: ['INLINE', 'MANAGED']
        },
        s3_policy: {
            $ref: 'common_api#/definitions/bucket_policy',
        },
    }
};
