/* Copyright (C) 2016 NooBaa */
'use strict';

module.exports = [{
    fields: {
        policy_arn: 1,
    },
    options: {
        unique: true,
        partialFilterExpression: {
            deleted: null,
        }
    }
}, ];
