/* Copyright (C) 2026 NooBaa */
'use strict';

module.exports = [{
    postgres: true,
    fields: {
        scope_id: 1,
        shard: 1,
    },
    options: {
        name: 'scope_id_shard_index',
        unique: false,
    }
}];
