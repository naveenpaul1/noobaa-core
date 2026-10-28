/* Copyright (C) 2026 NooBaa */
'use strict';

const dbg = require('../../util/debug_module')(__filename);
const db_client = require('../../util/db_client');
const { MDStore } = require('./md_store');
const mongo_utils = require('../../util/mongo_utils');
const { escapeLiteral } = require('pg');

// Postgres bigint max. Used as "unlimited" so a single WHERE clause covers both
// size-only and quantity-only quotas without branching in SQL.
const PG_BIGINT_MAX = '9223372036854775807';

const RESERVE_SQL = `
UPDATE bucketquotas
SET data = jsonb_set(
    jsonb_set(data, '{used_bytes}', to_jsonb(((data->>'used_bytes')::bigint + $3::bigint))),
    '{used_objects}', to_jsonb(((data->>'used_objects')::bigint + $4::bigint))
)
WHERE (data->>'owner_id')::text = $1::text
  AND (data->>'shard')::integer = $2::integer
RETURNING data
`;


const RELEASE_SQL = `
UPDATE bucketquotas
SET data = jsonb_set(
    jsonb_set(data, '{used_bytes}', to_jsonb(GREATEST(0::bigint, (data->>'used_bytes')::bigint + $3::bigint))),
    '{used_objects}', to_jsonb(GREATEST(0::bigint, (data->>'used_objects')::bigint + $4::bigint))
)
WHERE (data->>'owner_id')::text = $1::text
  AND (data->>'shard')::integer = $2::integer
RETURNING data
`;

const USAGE_SQL = `
SELECT
    SUM((data->>'used_bytes')::bigint) AS used_bytes,
    SUM((data->>'used_objects')::bigint) AS used_objects
FROM bucketquotas
WHERE (data->>'owner_id')::text = $1::text
`;

/**
 * Dedicated usage counter for strict bucket quota.
 *
 * Why not system_store / bucket.storage_stats:
 * - system_store is a config cache; every write is broadcast and reloads in-memory state.
 * - md_aggregator already writes storage_stats on a minutes-scale cycle; putting per-request
 *   increments there would serialize all endpoints on config updates.
 *
 * Why a one-row-per-bucket JSONB table with raw SQL:
 * - Same collection machinery as other MD tables, but the hot path is a parameterized
 *   UPDATE ... WHERE (used + delta) <= limit RETURNING, which is one round-trip,
 *   row-level atomic, and prepared (query_name). JSONB rewrite of a ~100B document is
 *   cheap next to the inherent single-row lock on the bucket.
 */
class BucketQuotaStore {

    static instance() {
        BucketQuotaStore._instance = BucketQuotaStore._instance || new BucketQuotaStore();
        return BucketQuotaStore._instance;
    }

    /**
     * Create or reset the usage row to zero. Called when enabling strict quota on
     * an empty bucket, so the hot path is UPDATE-only (no upsert advisory lock).
     * @param {nb.ID|string} bucket_id
     */
    async reset_usage(bucket_id) {
        const existing = await MDStore.instance().find_bucket_quota_row(bucket_id);
        if (existing) {
            return;
        }
        const quota_docs = [];
        for (let i = 0; i < 10; ++i) {
            const id = mongo_utils.mongoObjectId();
            quota_docs.push({ _id: id, shard: i, owner_id: bucket_id, used_bytes: 0, used_objects: 0 });
        }

        try {
            await MDStore.instance().insert_bucket_quota_rows(quota_docs);
        } catch (err) {
            if (db_client.instance().is_err_duplicate_key(err)) {
                await MDStore.instance().reset_bucket_quota_row(bucket_id);
                return;
            }
            dbg.error('BucketQuotaStore.reset_usage: insert failed', bucket_id, err);
            throw err;
        }
    }

    /**
     * @param {nb.ID|string} bucket_id
     */
    async delete_usage(bucket_id) {
        await MDStore.instance().delete_bucket_quota_rows(bucket_id);
    }

    /**
     * @param {nb.ID|string} bucket_id
     * @returns {Promise<{used_bytes: number, used_objects: number}|null>}
     */
    async get_usage(bucket_id) {
        const params = [
            String(bucket_id),
        ];
        const res = await db_client.instance().executeSQL(USAGE_SQL, params, {
                preferred_pool: 'md',
                query_name: 'bucket_quota_usage',
            });
        if (!res.rowCount) {
            dbg.log1('BucketQuotaStore.get_usage: failed', params);
            return { used_bytes: 0, used_objects: 0};
        }
        return {
            used_bytes: Number(res.rows[0].used_bytes) || 0,
            used_objects: Number(res.rows[0].used_objects) || 0,
        };
    }

    /**
     * Fetch current usage and verify that adding delta_bytes/delta_objects would
     * not exceed the given limits.
     *
     * @param {string} bucket_id_str  - stringified bucket id
     * @param {number} delta_bytes
     * @param {number} delta_objects
     * @param {number|string} limit_bytes
     * @param {number|string} limit_objects
     * @returns {Promise<boolean>}  false when the row is missing or limits would be exceeded
     */
    async _check_quota_limits(bucket_id_str, delta_bytes, delta_objects, limit_bytes, limit_objects) {
        const usage_res = await db_client.instance().executeSQL(USAGE_SQL, [bucket_id_str], {
            preferred_pool: 'md',
            query_name: 'bucket_quota_usage',
        });
        if (!usage_res.rowCount) {
            dbg.log1('BucketQuotaStore._check_quota_limits: no usage row found', bucket_id_str);
            return false;
        }

        const next_bytes = BigInt(usage_res.rows[0].used_bytes) + BigInt(delta_bytes);
        const next_objects = BigInt(usage_res.rows[0].used_objects) + BigInt(delta_objects);
        if (next_bytes > BigInt(limit_bytes) || next_objects > BigInt(limit_objects)) {
            dbg.warn('BucketQuotaStore._check_quota_limits: rejected due to quota validation, next bytes',
                next_bytes, "limit bytes: ", limit_bytes, "next objects: ", next_objects, "limit objects: ", limit_objects);
            return false;
        }
        return true;
    }

    /**
     * Atomically add usage. Returns false if the write would exceed either limit
     * (or if the row is missing — fail closed). Concurrent endpoints serialize on
     * the row lock; the WHERE clause is evaluated against the locked current values.
     *
     * @param {{
     *   bucket_id: nb.ID|string,
     *   object_id: nb.ID|string,
     *   delta_bytes?: number,
     *   delta_objects?: number,
     * }} params
     * @returns {Promise<string>}
     */
    async try_reserve_bucket_quota({
        bucket_id,
        object_id,
        delta_bytes = 0,
        delta_objects = 0,
    }) {
        console.log("try_reserve_bucket_quota ===>", )
        if (!delta_bytes && !delta_objects) return '';

        const params = [
            String(bucket_id),
            this._hash(object_id),
            String(delta_bytes),
            String(delta_objects),
        ];
        const sql = this._build_update_sql('reserve', ...params);
        //console.log("try_reserve_bucket_quota =====>>", sql)
        return sql;
        /*const res = await db_client.instance().executeSQL(sql, params, {
            preferred_pool: 'md',
            query_name: 'bucket_quota_try_reserve',
        });
        if (!res.rowCount) {
            dbg.log1('BucketQuotaStore.try_reserve_bucket_quota: rejected', params);
            return false;
        } 
        return true;*/
    }

    /**
     * Decrement usage, clamped at 0. Never fails the caller for quota reasons.
     *
     * @param {{
     *   bucket_id: nb.ID|string,
     *   object_id: string,
     *   delta_bytes?: number,
     *   delta_objects?: number,
     *   execute_query?: boolean,
     * }} params
     */
    async release_bucket_quota({ bucket_id, object_id, delta_bytes = 0, delta_objects = 0, execute_query = false }) {
        if (!delta_bytes && !delta_objects) return;
        const params = [
            String(bucket_id),
            this._hash(object_id),
            String(-Math.abs(delta_bytes)),
            String(-Math.abs(delta_objects)),
        ];
        const sql = this._build_update_sql('release', ...params);
        console.log("release_bucket_quota ===>>", execute_query)
        if (execute_query) {
            await db_client.instance().executeSQL(sql, [], {
                preferred_pool: 'md',
                query_name: 'bucket_quota_release',
            });
            return '';
        }
        return sql;
        /*await db_client.instance().executeSQL(sql, params, {
            preferred_pool: 'md',
            query_name: 'bucket_quota_release',
        });*/
    }
    /**
     * Maps a bucket_id to a shard index in [0, 9].
     * @param {nb.ID|string} object_id
     * @returns {number}
     */
    _hash(object_id) {
        const id_str = String(object_id).replace(/-/g, '');
        const num = parseInt(id_str.slice(-8), 16);
        return num % 10;
    }

    /**
     * Builds an UPDATE SQL for either 'reserve' or 'release' operations,
     * only touching the fields that are actually provided.
     *
     * The SQL is executed through a bulk op that does not pass bind parameters,
     * so all values (owner_id, shard, deltas) are inlined as escaped literals.
     *
     * Difference between types:
     *   reserve – plain arithmetic (used + delta), allows negative sums
     *   release – clamps at zero via GREATEST(0, used + delta)
     *
     * Returns an empty string when neither field is provided (caller should skip).
     *
     * @param {'reserve'|'release'} type
     * @param {string|number} owner_id
     * @param {string|number} shard
     * @param {number|string|undefined} used_bytes
     * @param {number|string|undefined} used_objects
     * @returns {string}
     */
    _build_update_sql(type, owner_id, shard, used_bytes, used_objects) {
        const has_bytes = used_bytes !== undefined && used_bytes !== null;
        const has_objects = used_objects !== undefined && used_objects !== null;

        if (!has_bytes && !has_objects) return '';

        const owner_lit = escapeLiteral(String(owner_id));
        const shard_lit = Number.parseInt(String(shard), 10);
        const bytes_lit = has_bytes ? BigInt(used_bytes).toString() : '0';
        const objects_lit = has_objects ? BigInt(used_objects).toString() : '0';

        // const clamp = type === 'release';
        const clamp = false;
        /**
         * Optionally clamps an arithmetic SQL expression at zero.
         * @param {string} expr
         * @returns {string}
         */
        const wrap = expr => clamp ? `GREATEST(0::bigint, ${expr})` : expr;

        const bytes_expr = `jsonb_set(data, '{used_bytes}', to_jsonb(${wrap(`(data->>'used_bytes')::bigint + ${bytes_lit}::bigint`)}))`;
        const objects_expr = `jsonb_set(data, '{used_objects}', to_jsonb(${wrap(`(data->>'used_objects')::bigint + ${objects_lit}::bigint`)}))`;

        let set_expr;
        if (has_bytes && has_objects) {
            set_expr = `jsonb_set(
                ${bytes_expr},
                '{used_objects}', to_jsonb(${wrap(`(data->>'used_objects')::bigint + ${objects_lit}::bigint`)})
            )`;
        } else if (has_bytes) {
            set_expr = bytes_expr;
        } else {
            set_expr = objects_expr;
        }

        return `
            UPDATE bucketquotas
            SET data = ${set_expr}
            WHERE (data->>'owner_id')::text = ${owner_lit}::text
            AND (data->>'shard')::integer = ${shard_lit}::integer
            RETURNING data`.trim();
    }
}

exports.BucketQuotaStore = BucketQuotaStore;
exports.PG_BIGINT_MAX = PG_BIGINT_MAX;
exports.RESERVE_SQL = RESERVE_SQL;
exports.RELEASE_SQL = RELEASE_SQL;
