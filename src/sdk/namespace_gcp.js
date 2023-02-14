/* Copyright (C) 2023 NooBaa */
'use strict';

const _ = require('lodash');
const util = require('util');

// const P = require('../util/promise');
const dbg = require('../util/debug_module')(__filename);
//TODO: why do we what to use the wrap and not directly @google-cloud/storage ? 
const GoogleCloudStorage = require('../util/google_storage_wrap');
const S3Error = require('../endpoint/s3/s3_errors').S3Error;

/**
 * @implements {nb.Namespace}
 */
class NamespaceGCP {


    constructor({ namespace_resource_id, rpc_client, project_id, target_bucket, client_email, private_key, access_mode }) {
        this.namespace_resource_id = namespace_resource_id;
        this.project_id = project_id;
        this.client_email = client_email;
        this.private_key = private_key;
        //gcs stands for google cloud storage
        this.gcs = new GoogleCloudStorage({
            projectId: this.project_id,
            credentials: {
                client_email: this.client_email,
                private_key: this.private_key,
            }
        });
        this.bucket = target_bucket;
        this.rpc_client = rpc_client;
        this.access_mode = access_mode;
    }

    get_write_resource() {
        return this;
    }

    is_server_side_copy(other, params) {
        //TODO: what is the case here, what determine server side copy? 
        return other instanceof NamespaceGCP &&
            this.private_key === other.private_key &&
            this.client_email === other.client_email;
    }

    get_bucket() {
        return this.bucket;
    }

    is_readonly_namespace() {
        if (this.access_mode && this.access_mode === 'READ_ONLY') {
            return true;
        }
        return false;
    }


    /////////////////
    // OBJECT LIST //
    /////////////////

    async list_objects(params, object_sdk) {
        dbg.log0('NamespaceGCP.list_objects:', this.bucket, inspect(params));
        throw new S3Error(S3Error.NotImplemented);
    }

    async list_uploads(params, object_sdk) {
        dbg.log0('NamespaceGCP.list_uploads:',
            this.bucket,
            inspect(params)
        );
        throw new S3Error(S3Error.NotImplemented);
    }

    async list_object_versions(params, object_sdk) {
        dbg.log0('NamespaceGCP.list_object_versions:',
            this.bucket,
            inspect(params)
        );
        throw new S3Error(S3Error.NotImplemented);
    }


    /////////////////
    // OBJECT READ //
    /////////////////

    async read_object_md(params, object_sdk) {
        dbg.log0('NamespaceGCP.read_object_md:', this.bucket, inspect(params));
        throw new S3Error(S3Error.NotImplemented);
    }

    async read_object_stream(params, object_sdk) {
        dbg.log0('NamespaceGCP.read_object_stream:', this.bucket, inspect(_.omit(params, 'object_md.ns')));
        throw new S3Error(S3Error.NotImplemented);
    }


    ///////////////////
    // OBJECT UPLOAD //
    ///////////////////

    async upload_object(params, object_sdk) {
        dbg.log0('NamespaceGCP.upload_object:', this.bucket, inspect(params));
        throw new S3Error(S3Error.NotImplemented);
    }

    /////////////////////////////
    // OBJECT MULTIPART UPLOAD //
    /////////////////////////////

    async create_object_upload(params, object_sdk) {
        dbg.log0('NamespaceGCP.create_object_upload:', this.bucket, inspect(params));
        throw new S3Error(S3Error.NotImplemented);
    }

    async upload_multipart(params, object_sdk) {
        dbg.log0('NamespaceGCP.upload_multipart:', this.bucket, inspect(params));
        throw new S3Error(S3Error.NotImplemented);
    }

    async list_multiparts(params, object_sdk) {
        dbg.log0('NamespaceGCP.list_multiparts:', this.bucket, inspect(params));
        throw new S3Error(S3Error.NotImplemented);
    }

    async complete_object_upload(params, object_sdk) {
        dbg.log0('NamespaceGCP.complete_object_upload:', this.bucket, inspect(params));
        throw new S3Error(S3Error.NotImplemented);
    }

    async abort_object_upload(params, object_sdk) {
        dbg.log0('NamespaceGCP.abort_object_upload:', this.bucket, inspect(params));
        throw new S3Error(S3Error.NotImplemented);
    }

    //////////
    // ACLs //
    //////////

    async get_object_acl(params, object_sdk) {
        dbg.log0('NamespaceGCP.get_object_acl:', this.bucket, inspect(params));
        throw new S3Error(S3Error.NotImplemented);
    }

    async put_object_acl(params, object_sdk) {
        dbg.log0('NamespaceGCP.put_object_acl:', this.bucket, inspect(params));
        throw new S3Error(S3Error.NotImplemented);
    }

    ///////////////////
    // OBJECT DELETE //
    ///////////////////

    async delete_object(params, object_sdk) {
        // https://googleapis.dev/nodejs/storage/latest/File.html#delete
        dbg.log0('NamespaceGCP.delete_object:', this.bucket, inspect(params));
        throw new S3Error(S3Error.NotImplemented);
    }

    async delete_multiple_objects(params, object_sdk) {
        // https://googleapis.dev/nodejs/storage/latest/File.html#delete
        dbg.log0('NamespaceGCP.delete_multiple_objects:', this.bucket, inspect(params));
        throw new S3Error(S3Error.NotImplemented);
    }


    ////////////////////
    // OBJECT TAGGING //
    ////////////////////

    async get_object_tagging(params, object_sdk) {
        throw new Error('TODO');
    }
    async delete_object_tagging(params, object_sdk) {
        throw new Error('TODO');
    }
    async put_object_tagging(params, object_sdk) {
        throw new Error('TODO');
    }

    ///////////////////
    //  OBJECT LOCK  //
    ///////////////////

    async get_object_legal_hold() {
        throw new Error('TODO');
    }
    async put_object_legal_hold() {
        throw new Error('TODO');
    }
    async get_object_retention() {
        throw new Error('TODO');
    }
    async put_object_retention() {
        throw new Error('TODO');
    }

    ///////////////////
    //      ULS      //
    ///////////////////

    async create_uls() {
        throw new Error('TODO');
    }
    async delete_uls() {
        throw new Error('TODO');
    }

    ///////////////
    // INTERNALS //
    ///////////////

    //TODO: add here the internal functions

    _translate_error_code(err) {
        // https://cloud.google.com/storage/docs/json_api/v1/status-codes
        if (err.code === 404) err.rpc_code = 'NO_SUCH_OBJECT';
        if (err.code === 403) err.rpc_code = 'FORBIDDEN';
    }
}

function inspect(x) {
    return util.inspect(_.omit(x, 'source_stream'), true, 5, true);
}

module.exports = NamespaceGCP;