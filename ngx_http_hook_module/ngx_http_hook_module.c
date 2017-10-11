
/*
 * Copyright (C) onestraw (hexiaowei91@gmail.com)
 */

#include <ngx_http_hook_module.h>


static ngx_http_module_t  ngx_http_hook_module_ctx = {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};


ngx_module_t  ngx_http_hook_module = {
    NGX_MODULE_V1,
    &ngx_http_hook_module_ctx,             /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};



static struct ngx_hook_operations *hook_ops = NULL;


ngx_int_t
ngx_hook_register_ops(struct ngx_hook_operations *ops)
{
    if (!ops) {
        return NGX_ERROR;
    }
    hook_ops = ops;
    return NGX_OK;
}


ngx_int_t
ngx_hook_http_upstream_init_round_robin_peers(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "call %s ...", __FUNCTION__);

    if (!hook_ops || !hook_ops->http_upstream_init_round_robin_peers) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0, 
                "hook_ops or http_upstream_init_round_robin_peers is null");
        return NGX_ERROR;
    }
    return hook_ops->http_upstream_init_round_robin_peers(cf, us);
}


ngx_int_t
ngx_hook_http_upstream_init_round_robin_backup(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us)
{
    if (!hook_ops || !hook_ops->http_upstream_init_round_robin_backup) {
        return NGX_ERROR;
    }
    return hook_ops->http_upstream_init_round_robin_backup(cf, us);
}


ngx_int_t
ngx_hook_http_upstream_init_round_robin_implicitly_defined(
    ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
{
    if (!hook_ops
            || !hook_ops->http_upstream_init_round_robin_implicitly_defined) {
        return NGX_ERROR;
    }
    return hook_ops->http_upstream_init_round_robin_implicitly_defined(
            cf, us);
}


ngx_int_t
ngx_hook_http_upstream_create_round_robin_peer(ngx_http_request_t *r,
    ngx_http_upstream_resolved_t *ur)
{
    if (!hook_ops || !hook_ops->http_upstream_create_round_robin_peer) {
        return NGX_ERROR;
    }
    return hook_ops->http_upstream_create_round_robin_peer(r, ur);
}


ngx_int_t
ngx_hook_http_upstream_get_round_robin_peer(ngx_peer_connection_t *pc,
        ngx_http_upstream_rr_peer_t *peer)
{
    if (!hook_ops || !hook_ops->http_upstream_get_round_robin_peer) {
        return NGX_ERROR;
    }
    return hook_ops->http_upstream_get_round_robin_peer(pc, peer);
}


ngx_int_t
ngx_hook_http_upstream_get_least_conn_peer(ngx_peer_connection_t *pc,
        ngx_http_upstream_rr_peer_t *peer)
{
    if (!hook_ops || !hook_ops->http_upstream_get_least_conn_peer) {
        return NGX_ERROR;
    }
    return hook_ops->http_upstream_get_least_conn_peer(pc, peer);
}


ngx_int_t
ngx_hook_http_upstream_get_hash_peer(ngx_peer_connection_t *pc,
        ngx_http_upstream_rr_peer_t *peer)
{
    if (!hook_ops || !hook_ops->http_upstream_get_hash_peer) {
        return NGX_ERROR;
    }
    return hook_ops->http_upstream_get_hash_peer(pc, peer);
}


ngx_int_t
ngx_hook_http_upstream_get_chash_peer(ngx_peer_connection_t *pc,
        ngx_http_upstream_rr_peer_t *peer)
{
    if (!hook_ops || !hook_ops->http_upstream_get_chash_peer) {
        return NGX_ERROR;
    }
    return hook_ops->http_upstream_get_chash_peer(pc, peer);
}


ngx_int_t
ngx_hook_http_upstream_get_ip_hash_peer(ngx_peer_connection_t *pc,
        ngx_http_upstream_rr_peer_t *peer)
{
    if (!hook_ops || !hook_ops->http_upstream_get_ip_hash_peer) {
        return NGX_ERROR;
    }
    return hook_ops->http_upstream_get_ip_hash_peer(pc, peer);
}
