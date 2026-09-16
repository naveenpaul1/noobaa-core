/* Copyright (C) 2026 NooBaa */
'use strict';

const dbg = require('../../util/debug_module')(__filename);
const { RpcError } = require('../../rpc');
const db_client = require('../../util/db_client');
const { MDStore } = require('./md_store');
const Quota = require('../system_services/objects/quota');

function is_enabled(bucket) {
    return Boolean(bucket && bucket.quota && bucket.quota.enforce_quota);
}

function _bucket_name(bucket) {
    return bucket.name && bucket.name.unwrap ? bucket.name.unwrap() : String(bucket._id);
}

function _buckets_col() {
    return db_client.instance().collection('buckets');
}

/**
 * Atomically reserves `size_bytes` bytes and `quantity` objects in the bucket's
 * realtime quota counters when `enforce_quota` mode is active.
 *
 * Uses a conditional findOneAndUpdate (WHERE quota_size_used <= limit - size AND
 * quota_quantity_used <= quantity_limit - quantity) so that the operation is a
 * no-op and returns null if the reservation would push usage over the limit.
 *
 * @param {Object} bucket
 * @param {number|undefined} size_bytes
 * @param {number} quantity
 * @returns {Promise<{reserve_size: number, reserve_quantity: number}|undefined>}
 */
async function enforce(bucket, size_bytes, quantity) {
    console.log("ENFORCE ======>>>", size_bytes, quantity)
    if (!is_enabled(bucket)) return;

    const quota = new Quota(bucket.quota);
    const size_limit = quota.get_size_limit_bytes();
    const quantity_limit = quota.get_quantity_limit();

    const filter = { _id: bucket._id };
    const inc = {};

    const reserve_size = (size_bytes !== undefined && size_bytes >= 0) ? size_bytes : 0;
    const reserve_quantity = quantity || 0;

    if (size_limit > 0) {
        // Only allow the increment when current_used + reserve_size <= size_limit
        filter.quota_size_used = { $lte: size_limit - reserve_size };
        inc.quota_size_used = reserve_size;
    }

    if (quantity_limit > 0) {
        filter.quota_quantity_used = { $lte: quantity_limit - reserve_quantity };
        inc.quota_quantity_used = reserve_quantity;
    }

    if (Object.keys(inc).length === 0) {
        return;
    }

    const res = await _buckets_col().findOneAndUpdate(
        filter,
        { $inc: inc },
        { returnOriginal: false }
    );

    if (!res || !res.value) {
        dbg.warn('enforce_realtime_quota: quota exceeded for bucket', _bucket_name(bucket),
            { reserve_size, reserve_quantity, size_limit, quantity_limit });
        throw new RpcError('REALTIME_QUOTA_EXCEEDED',
            `Upload rejected: would exceed the bucket's configured quota limit`);
    }

    return { reserve_size, reserve_quantity };
}

/**
 * Unconditional counter adjustment (credits / rollback). Never used to consume
 * additional quota — positive deltas must go through `enforce()`.
 *
 * @param {Object} bucket
 * @param {number} reserved_size
 * @param {number} reserved_quantity
 */
async function release(bucket, reserved_size, reserved_quantity) {
    if (!is_enabled(bucket)) return;
    if (!reserved_size && !reserved_quantity) return;

    const quota = new Quota(bucket.quota);
    const size_limit = quota.get_size_limit_bytes();
    const quantity_limit = quota.get_quantity_limit();

    const inc = {};
    if (size_limit > 0 && reserved_size) inc.quota_size_used = -reserved_size;
    if (quantity_limit > 0 && reserved_quantity) inc.quota_quantity_used = -reserved_quantity;
    if (Object.keys(inc).length === 0) return;

    await _buckets_col().updateOne({ _id: bucket._id }, { $inc: inc });
}

async function _safe_release(bucket, reserved_size, reserved_quantity, context) {
    try {
        await release(bucket, reserved_size, reserved_quantity);
    } catch (err) {
        dbg.error('failed to release realtime quota', context, err);
    }
}

/**
 * Credits committed objects that were actually removed from MD.
 * Delete markers release a quantity only (they have no size).
 * In-progress uploads are skipped — abort/lifecycle uses release_for_aborted_uploads.
 *
 * @param {Object} bucket
 * @param {Object|Object[]} deleted_objs
 */
async function release_for_deleted(bucket, deleted_objs) {
    if (!is_enabled(bucket)) return;

    const quota = new Quota(bucket.quota);
    const size_limit = quota.get_size_limit_bytes();
    const quantity_limit = quota.get_quantity_limit();
    if (!size_limit && !quantity_limit) return;

    const objs = Array.isArray(deleted_objs) ? deleted_objs : [deleted_objs];

    let total_size = 0;
    let total_quantity = 0;
    for (const obj of objs) {
        if (!obj) continue;
        if (obj.upload_started) continue;
        if (obj.delete_marker) {
            total_quantity += 1;
            continue;
        }
        if (!(obj.size >= 0)) continue;
        total_size += obj.size;
        total_quantity += 1;
    }

    if (!total_size && !total_quantity) return;

    const inc = {};
    if (size_limit > 0 && total_size > 0) inc.quota_size_used = -total_size;
    if (quantity_limit > 0 && total_quantity > 0) inc.quota_quantity_used = -total_quantity;
    if (!Object.keys(inc).length) return;

    await _buckets_col().updateOne({ _id: bucket._id }, { $inc: inc });
}

/**
 * Releases reservations held by in-progress uploads that were aborted (explicit
 * abort or lifecycle abort-incomplete-MPU). Uses the reserved_* fields, not size.
 *
 * @param {Object} bucket
 * @param {Object|Object[]} objs
 */
async function release_for_aborted_uploads(bucket, objs) {
    if (!is_enabled(bucket)) return;
    const list = Array.isArray(objs) ? objs : [objs];
    let total_size = 0;
    let total_quantity = 0;
    for (const obj of list) {
        if (!obj) continue;
        total_size += obj.realtime_quota_reserved_size || 0;
        total_quantity += obj.realtime_quota_reserved_quantity || 0;
    }
    await release(bucket, total_size, total_quantity);
}

/**
 * ENABLED/SUSPENDED DeleteObject without versionId always creates a delete marker,
 * which counts toward quantity quota. Reserve the slot before creating the marker.
 *
 * @param {Object} req
 * @returns {Promise<boolean>} true if a quantity slot was reserved
 */
async function reserve_delete_marker_if_needed(req) {
    if (!is_enabled(req.bucket)) return false;
    if (req.rpc_params.version_id) return false;
    const versioning = req.bucket.versioning;
    if (versioning !== 'ENABLED' && versioning !== 'SUSPENDED') return false;
    await enforce(req.bucket, 0, 1);
    return true;
}

/**
 * Looks up the currently-committed object for the same key (if any).
 * Returns null when enforce_quota is inactive or versioning is ENABLED
 * (each upload is a new version — no overwrite credit applies).
 *
 * @param {Object} req
 * @param {string} key
 * @returns {Promise<{exists: boolean, size: number}|null>}
 */
async function get_overwrite_info(req, key) {
    if (!is_enabled(req.bucket)) return null;
    if (req.bucket.versioning === 'ENABLED') return null;

    const existing = await MDStore.instance().find_object_null_version(req.bucket._id, key);
    if (!existing) return { exists: false, size: 0 };
    return { exists: true, size: existing.size >= 0 ? existing.size : 0 };
}

/**
 * Prefer reserved_* from DB so MPU part $inc values are not lost to object_md_cache.
 * Falls back to the in-memory object (deferred create that never inserted).
 *
 * @param {Object} obj
 */
async function load_reserved_object(obj) {
    console.log("load_reserved_object_quota ===>>", obj._id, obj)
    const from_obj = {
        reserved_size: obj.realtime_quota_reserved_size || 0,
        reserved_quantity: obj.realtime_quota_reserved_quantity || 0,
    };
    if (!obj._id) return from_obj;
    const obj_id = typeof obj._id === 'string' ? MDStore.instance().make_md_id(obj._id) : obj._id;
    const fresh = await MDStore.instance().find_object_by_id(obj_id);
    if (!fresh) return from_obj;
    return {
        reserved_size: fresh.realtime_quota_reserved_size || 0,
        reserved_quantity: fresh.realtime_quota_reserved_quantity || 0,
    };
}

/**
 * Before committing the object: if final size (minus overwrite credit) exceeds
 * what was already reserved, take the remainder with the atomic WHERE guard.
 *
 * @param {Object} bucket
 * @param {Object} obj
 * @param {number} final_size
 * @param {{exists: boolean, size: number}|null} overwrite_info
 */
async function prepare_complete(bucket, obj, final_size, overwrite_info) {
    if (!is_enabled(bucket)) {
        return { extra_size: 0, reserved_size: 0, reserved_quantity: 0 };
    }
    const reserved = await load_reserved_object(obj);
    const overwritten_size = overwrite_info ? overwrite_info.size : 0;
    const net_size = final_size - reserved.reserved_size - overwritten_size;
    let extra_size = 0;
    if (net_size > 0) {
        await enforce(bucket, net_size, 0);
        extra_size = net_size;
    }
    return { extra_size, ...reserved };
}

/**
 * After a successful commit: credit leftover reservation and overwritten storage.
 * Size leftover is <= 0 when prepare_complete ran first.
 *
 * @param {Object} bucket
 * @param {Object} obj
 * @param {number} final_size
 * @param {{exists: boolean, size: number}|null} overwrite_info
 * @param {{extra_size: number, reserved_size: number, reserved_quantity: number}} prep
 */
async function finalize_complete(bucket, _obj, final_size, overwrite_info, prep) {
    if (!is_enabled(bucket)) return;

    const overwritten_size = overwrite_info ? overwrite_info.size : 0;
    const is_overwrite = overwrite_info ? overwrite_info.exists : false;
    const reserved_size = prep.reserved_size || 0;
    const reserved_quantity = prep.reserved_quantity || 0;
    const extra_size = prep.extra_size || 0;

    const net_size = final_size - reserved_size - extra_size - overwritten_size;
    const net_qty = is_overwrite ? -reserved_quantity : 0;

    if (net_size > 0) {
        // Defensive: leftover consume should have happened in prepare_complete.
        await enforce(bucket, net_size, 0);
    }

    const inc = {};
    const quota = new Quota(bucket.quota);
    if (net_size < 0 && quota.get_size_limit_bytes() > 0) {
        inc.quota_size_used = net_size;
    }
    if (net_qty !== 0 && quota.get_quantity_limit() > 0) {
        inc.quota_quantity_used = net_qty;
    }
    if (Object.keys(inc).length > 0) {
        await _buckets_col().updateOne({ _id: bucket._id }, { $inc: inc });
    }
}

/**
 * Reserve any extra size needed, run `commit_fn`, then credit overwrite / leftover.
 * Rolls back the extra reservation if commit fails.
 *
 * @param {Object} req
 * @param {Object} obj
 * @param {number} final_size
 * @param {() => Promise<any>} commit_fn
 */
async function apply_on_complete(req, obj, final_size, commit_fn) {
    console.log("apply_on_complete ===>>>", final_size)
    const overwrite_info = await get_overwrite_info(req, obj.key);
    const prep = await prepare_complete(req.bucket, obj, final_size, overwrite_info);
    try {
        const result = await commit_fn();
        await finalize_complete(req.bucket, obj, final_size, overwrite_info, prep);
        return result;
    } catch (err) {
        if (prep.extra_size) {
            await _safe_release(req.bucket, prep.extra_size, 0, 'complete rollback');
        }
        throw err;
    }
}

exports.is_enabled = is_enabled;
exports.enforce = enforce;
exports.release = release;
exports.release_for_deleted = release_for_deleted;
exports.release_for_aborted_uploads = release_for_aborted_uploads;
exports.reserve_delete_marker_if_needed = reserve_delete_marker_if_needed;
exports.apply_on_complete = apply_on_complete;
