# why do we need nginx hook extension

In production, maybe we have to enhance Nginx core,
but sometimes we cannot make it by writing independent modules,
in other words, we have to modify Nginx core though looks ugly,
and if there are several functions need to change core code,
it will be hard to upgrade Nginx in future.


such as ngx_http_stub_status_module
```bash
root:nginx-1.9.2# grep STAT_STUB -rn src/
src/mail/ngx_mail_handler.c:840:#if (NGX_STAT_STUB)
src/event/ngx_event_accept.c:137:#if (NGX_STAT_STUB)
src/event/ngx_event_accept.c:157:#if (NGX_STAT_STUB)
src/event/ngx_event_accept.c:260:#if (NGX_STAT_STUB)
src/event/ngx_event_accept.c:419:#if (NGX_STAT_STUB)
src/event/ngx_event_accept.c:443:#if (NGX_STAT_STUB)
src/event/ngx_event_accept.c:583:#if (NGX_STAT_STUB)
src/event/ngx_event_accept.c:760:#if (NGX_STAT_STUB)
src/event/ngx_event.h:478:#if (NGX_STAT_STUB)
src/event/ngx_event.c:60:#if (NGX_STAT_STUB)
src/event/ngx_event.c:490:#if (NGX_STAT_STUB)
src/event/ngx_event.c:536:#if (NGX_STAT_STUB)
src/core/ngx_connection.c:1209:#if (NGX_STAT_STUB)
src/core/ngx_connection.c:1223:#if (NGX_STAT_STUB)
src/http/ngx_http_request.c:619:#if (NGX_STAT_STUB)
src/http/ngx_http_request.c:1937:#if (NGX_STAT_STUB)
src/http/ngx_http_request.c:3484:#if (NGX_STAT_STUB)
src/http/ngx_http_request.c:3579:#if (NGX_STAT_STUB)
src/stream/ngx_stream_handler.c:347:#if (NGX_STAT_STUB)
```

and thirdparty module [nginx_upstream_check_module](https://github.com/yaoweibin/nginx_upstream_check_module)

# how to use this module
```bash
version=1.13.5
NGX=nginx-$version

wget http://nginx.org/download/$NGX.tar.gz
tar xvf $NGX.tar.gz


# * generate patch
#   diff -Naur nginx-1.13.5/src/ nginx-1.13.5.patch/src/ >nginx-hook.patch
#
# * apply patch
cd $NGX
patch -p1 < nginx-hook.patch
./configure \
        --prefix=`pwd`/nginx-install \
        --with-debug \
        --add-module=../ngx_http_hook_module \
        --add-module=../nginx_upstream_check_module

make -j4 && make install

# run test
# apt-get install libtest-base-perl libipc-run3-perl libtest-longstring-perl
# 1. goto path nginx_upstream_check_module/test
# 2. modify test.sh to pointer your new build nginx path
# 3. make sure exec test.sh with non-root or append 'user root;' to test/lib/Test/Nginx/Util.pm line 374
# 4. ./test.sh
```
