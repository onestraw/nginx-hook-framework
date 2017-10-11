
/*
 * Copyright (C) onestraw (hexiaowei91@gmail.com)
 */


#ifndef _NGX_HOOK_MODULE_INCLUDED_
#define _NGX_HOOK_MODULE_INCLUDED_

#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HOOK_NAME_MAX   32


typedef ngx_int_t (*http_upstream_get_peer_func) (
        ngx_peer_connection_t *pc, ngx_http_upstream_rr_peer_t *peer);


struct ngx_hook_operations {
    char name[NGX_HOOK_NAME_MAX + 1];

    ngx_int_t (*http_upstream_init_round_robin_peers) (ngx_conf_t *cf,
        ngx_http_upstream_srv_conf_t *us);
    ngx_int_t (*http_upstream_init_round_robin_backup) (ngx_conf_t *cf,
        ngx_http_upstream_srv_conf_t *us);
    ngx_int_t (*http_upstream_init_round_robin_implicitly_defined) (
        ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us);
    ngx_int_t (*http_upstream_create_round_robin_peer) (ngx_http_request_t *r,
        ngx_http_upstream_resolved_t *ur);
    http_upstream_get_peer_func http_upstream_get_round_robin_peer;
    http_upstream_get_peer_func http_upstream_get_least_conn_peer;
    http_upstream_get_peer_func http_upstream_get_hash_peer;
    http_upstream_get_peer_func http_upstream_get_chash_peer;
    http_upstream_get_peer_func http_upstream_get_ip_hash_peer;
};


ngx_int_t ngx_hook_http_upstream_init_round_robin_peers(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);
ngx_int_t ngx_hook_http_upstream_init_round_robin_backup(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);
ngx_int_t ngx_hook_http_upstream_init_round_robin_implicitly_defined(
    ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us);
ngx_int_t ngx_hook_http_upstream_create_round_robin_peer(ngx_http_request_t *r,
    ngx_http_upstream_resolved_t *ur);
ngx_int_t ngx_hook_http_upstream_get_round_robin_peer(ngx_peer_connection_t *pc,
    ngx_http_upstream_rr_peer_t *peer);
ngx_int_t ngx_hook_http_upstream_get_hash_peer(ngx_peer_connection_t *pc,
    ngx_http_upstream_rr_peer_t *peer);
ngx_int_t ngx_hook_http_upstream_get_chash_peer(ngx_peer_connection_t *pc,
    ngx_http_upstream_rr_peer_t *peer);
ngx_int_t ngx_hook_http_upstream_get_ip_hash_peer(ngx_peer_connection_t *pc,
    ngx_http_upstream_rr_peer_t *peer);
ngx_int_t ngx_hook_http_upstream_get_least_conn_peer(ngx_peer_connection_t *pc,
    ngx_http_upstream_rr_peer_t *peer);

ngx_int_t ngx_hook_register_ops(struct ngx_hook_operations *ops);
ngx_int_t ngx_hook_interface_init(ngx_cycle_t *cycle);


#endif /* _NGX_HOOK_MODULE_INCLUDED_ */
