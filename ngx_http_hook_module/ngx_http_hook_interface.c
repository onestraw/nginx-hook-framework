
/*
 * Copyright (C) onestraw (hexiaowei91@gmail.com)
 */

#include <ngx_http_hook_module.h>
#include <ngx_http_upstream_check_module.h>


ngx_int_t ngx_hook_http_upstream_init_rr_peers(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);
ngx_int_t ngx_hook_http_upstream_init_rr_backup(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);
ngx_int_t ngx_hook_http_upstream_init_rr_implicitly_defined(
    ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us);
ngx_int_t ngx_hook_http_upstream_create_rr_peer(ngx_http_request_t *r,
    ngx_http_upstream_resolved_t *ur);
ngx_int_t ngx_hook_http_upstream_get_rr_peer(ngx_peer_connection_t *pc,
    ngx_http_upstream_rr_peer_t *peer);


static struct ngx_hook_operations ngx_hook_ops = {
    .name = "check hook",
    .http_upstream_init_round_robin_peers = ngx_hook_http_upstream_init_rr_peers,
    .http_upstream_init_round_robin_backup = ngx_hook_http_upstream_init_rr_backup,
    .http_upstream_init_round_robin_implicitly_defined = ngx_hook_http_upstream_init_rr_implicitly_defined,
    .http_upstream_create_round_robin_peer = ngx_hook_http_upstream_create_rr_peer,
    .http_upstream_get_round_robin_peer = ngx_hook_http_upstream_get_rr_peer,
    .http_upstream_get_least_conn_peer = ngx_hook_http_upstream_get_rr_peer,
    .http_upstream_get_hash_peer = ngx_hook_http_upstream_get_rr_peer,
    .http_upstream_get_chash_peer = ngx_hook_http_upstream_get_rr_peer,
    .http_upstream_get_ip_hash_peer = ngx_hook_http_upstream_get_rr_peer
};


typedef struct ngx_http_upstream_rr_peer_extension_s {
    ngx_uint_t  check_index;
} ngx_http_upstream_rr_peer_ext_t;



ngx_int_t
ngx_hook_interface_init(ngx_cycle_t *cycle)
{
    struct ngx_hook_operations *hook_ops;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0, "init hook interface");

    hook_ops = ngx_pcalloc(cycle->pool, sizeof(struct ngx_hook_operations));

    if (hook_ops == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(hook_ops, &ngx_hook_ops, sizeof(struct ngx_hook_operations));

    return ngx_hook_register_ops(hook_ops);
}


static ngx_inline ngx_int_t
ngx_hook_http_upstream_set_peer(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us, ngx_http_upstream_rr_peer_t *peer)
{
    ngx_addr_t                      *addr;
    ngx_http_upstream_rr_peer_ext_t *peer_ext;

    peer_ext = ngx_pcalloc(cf->pool,
            sizeof(ngx_http_upstream_rr_peer_ext_t));

    if (peer_ext == NULL) {
        return NGX_ERROR;
    }

    if (!peer->down) {
        addr = ngx_pcalloc(cf->pool, sizeof(ngx_addr_t));
        if (addr == NULL) {
            return NGX_ERROR;
        }

        addr->sockaddr = peer->sockaddr;
        addr->socklen = peer->socklen;
        addr->name = peer->name;
        peer_ext->check_index = ngx_http_upstream_check_add_peer(
                cf, us, addr);

    } else {
        peer_ext->check_index = (ngx_uint_t) NGX_ERROR;
    }

    peer->hook_data = peer_ext;

    return NGX_OK;
}


ngx_int_t
ngx_hook_http_upstream_init_rr_peers(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_uint_t                       i;
    ngx_http_upstream_rr_peer_t     *peer;
    ngx_http_upstream_rr_peers_t    *peers;

    peers = us->peer.data;
    peer = peers->peer;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "%s", __FUNCTION__);

    for (i = 0; i < peers->number; i++) {
        if (ngx_hook_http_upstream_set_peer(cf, us, &peer[i]) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_hook_http_upstream_init_rr_backup(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_uint_t                       i;
    ngx_http_upstream_rr_peer_t     *peer;
    ngx_http_upstream_rr_peers_t    *peers, *backup;

    peers = us->peer.data;
    backup = peers->next;
    peer = backup->peer;

    for (i = 0; i < backup->number; i++) {
        if (ngx_hook_http_upstream_set_peer(cf, us, &peer[i]) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_hook_http_upstream_init_rr_implicitly_defined(
    ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
{
    ngx_uint_t                       i;
    ngx_http_upstream_rr_peer_t     *peer;
    ngx_http_upstream_rr_peers_t    *peers;
    ngx_http_upstream_rr_peer_ext_t *peer_ext;

    peers = us->peer.data;
    peer = peers->peer;

    for (i = 0; i < peers->number; i++) {
        peer_ext = ngx_pcalloc(cf->pool,
                sizeof(ngx_http_upstream_rr_peer_ext_t));

        if (peer_ext == NULL) {
            return NGX_ERROR;
        }

        peer_ext->check_index = (ngx_uint_t) NGX_ERROR;
        peer[i].hook_data = peer_ext;
    }

    return NGX_OK;
}


ngx_int_t
ngx_hook_http_upstream_create_rr_peer(ngx_http_request_t *r,
    ngx_http_upstream_resolved_t *ur)
{
    ngx_uint_t                         i;
    ngx_http_upstream_rr_peer_t       *peer;
    ngx_http_upstream_rr_peers_t      *peers;
    ngx_http_upstream_rr_peer_data_t  *rrp;
    ngx_http_upstream_rr_peer_ext_t   *peer_ext;

    rrp = r->upstream->peer.data;
    peers = rrp->peers;
    peer = peers->peer;

    if (ur->sockaddr) {
        peer_ext = ngx_pcalloc(r->pool,
                sizeof(ngx_http_upstream_rr_peer_ext_t));

        if (peer_ext == NULL) {
            return NGX_ERROR;
        }

        peer[0].hook_data = peer_ext;

    } else {

        for (i = 0; i < peers->number; i++) {
            peer_ext = ngx_pcalloc(r->pool, sizeof(ngx_uint_t));

            if (peer_ext == NULL) {
                return NGX_ERROR;
            }

            peer[i].hook_data = peer_ext;
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_hook_http_upstream_get_rr_peer(ngx_peer_connection_t *pc,
        ngx_http_upstream_rr_peer_t *peer)
{
    ngx_http_upstream_rr_peer_ext_t   *peer_ext;

    peer_ext = (ngx_http_upstream_rr_peer_ext_t *) peer->hook_data;

    if (pc) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                       "get rr peer, peer_ext: %p", &peer_ext);
        if (!peer_ext) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "peer_ext is null");
        }
    }

    if (!peer_ext || ngx_http_upstream_check_peer_down(peer_ext->check_index)) {
        return NGX_ERROR;
    }

    return NGX_OK;
}
