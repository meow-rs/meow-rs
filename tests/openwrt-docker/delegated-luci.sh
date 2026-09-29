#!/bin/sh
# Runs inside the disposable router; exercise a meow-only login, not root ACLs.
set -eu
uci set rpcd.meow_review=login
uci set rpcd.meow_review.username=meow-review
uci set 'rpcd.meow_review.password=$p$root'
uci add_list rpcd.meow_review.read=luci-app-meow
uci add_list rpcd.meow_review.write=luci-app-meow
uci commit rpcd
/etc/init.d/rpcd restart
sleep 1
sid=$(ubus call session login '{"username":"meow-review","password":""}' | jsonfilter -e '@.ubus_rpc_session')
[ -n "$sid" ]
# uhttpd enforces the ubus transport ACL; rpcd additionally checks file paths.
rpc() {
    curl --noproxy '*' -fsS -H 'Content-Type: application/json' --data \
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"call\",\"params\":[\"$sid\",\"file\",\"$1\",$2]}" http://127.0.0.1/ubus
}
result=$(rpc exec '{"command":"/usr/libexec/meow-api","params":["GET","/version"]}')
[ "$(jsonfilter -s "$result" -e '@.result[0]')" = 0 ]
[ "$(jsonfilter -s "$result" -e '@.result[1].code')" = 0 ]
result=$(rpc exec '{"command":"/bin/sh","params":["-c","true"]}')
[ "$(jsonfilter -s "$result" -e '@.result[0]')" != 0 ]
# file.write is intentionally unavailable: CGI upload cannot chmod a YAML
# payload executable. The exact config path is the only persistent write grant.
result=$(rpc write '{"path":"/etc/meow/config.yaml","data":"bad","mode":493}')
[ "$(jsonfilter -s "$result" -e '@.result[0]')" != 0 ]
curl --noproxy '*' -fsS --data-urlencode "sessionid=$sid" --data-urlencode 'path=/etc/meow/config.yaml' \
    http://127.0.0.1/cgi-bin/cgi-download > /tmp/meow-delegated-download
cmp /tmp/meow-delegated-download /etc/meow/config.yaml
printf 'rules: [MATCH,DIRECT]\n' > /tmp/meow-upload-source
curl --noproxy '*' -fsS -F "sessionid=$sid" -F filename=/tmp/meow-luci-check.yaml \
    -F filedata=@/tmp/meow-upload-source http://127.0.0.1/cgi-bin/cgi-upload > /tmp/meow-upload-result
cmp /tmp/meow-upload-source /tmp/meow-luci-check.yaml
result=$(rpc exec '{"command":"/usr/libexec/meow-validate","params":["check"]}')
[ "$(jsonfilter -s "$result" -e '@.result[1].code')" = 0 ]
result=$(rpc exec '{"command":"/usr/libexec/meow-validate","params":["check","-v"]}')
[ "$(jsonfilter -s "$result" -e '@.result[1].code')" != 0 ]
result=$(rpc exec '{"command":"/usr/libexec/meow-validate","params":["check -v"]}')
[ "$(jsonfilter -s "$result" -e '@.result[1].code')" != 0 ]
result=$(rpc remove '{"path":"/tmp/meow-luci-check.yaml"}')
[ "$(jsonfilter -s "$result" -e '@.result[0]')" = 0 ]
uci delete rpcd.meow_review
uci commit rpcd
rm -f /tmp/meow-delegated-download /tmp/meow-upload-source /tmp/meow-upload-result
printf 'DELEGATED_OK\n'
