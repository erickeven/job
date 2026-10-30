#!/bin/bash
# ==============================================================================
# Project: REALITY SNI Ultimate Scanner & Validator (Zero-Footprint Edition)
# Repo   : https://github.com/erickeven/job
# Usage  : bash <(curl -sL https://raw.githubusercontent.com/erickeven/job/main/sni.sh)
# Clean  : bash <(curl -sL https://raw.githubusercontent.com/erickeven/job/main/sni.sh) clean
# ==============================================================================

export LC_ALL=C

# 清理历史残留垃圾函数
clean_legacy_junk() {
    local dirs=("." "/root" "/etc/v2node" "/tmp")
    for d in "${dirs[@]}"; do
        rm -f "$d/scanner" "$d/result.csv" "$d/find_sni.sh" "$d/find_sni_pro.sh" "$d/sni_pro_result.txt" 2>/dev/null
    done
    rm -rf /tmp/reality_sni_* 2>/dev/null
}

# 如果传入 clean 或 uninstall 参数，仅执行彻底清理并退出
if [[ "$1" =~ ^(clean|uninstall|-c|--clean|--uninstall)$ ]]; then
    clean_legacy_junk
    rm -f /usr/local/bin/sni 2>/dev/null
    echo "✅ 已彻底清理本机所有扫描器、CSV 结果及历史残留脚本，VPS 已恢复纯净状态！"
    exit 0
fi

# 创建独立内存沙盒目录，并注册退出自动销毁钩子 (含 Ctrl+C 中断保护)
WORK_DIR=$(mktemp -d /tmp/reality_sni_XXXXXX)
cleanup() {
    rm -rf "$WORK_DIR" 2>/dev/null
    clean_legacy_junk
}
trap cleanup EXIT INT TERM

# 1. 自动获取本机公网 IP、网段、所在国家及 CPU 架构
IP_INFO=$(curl -s4m4 https://ipinfo.io/json 2>/dev/null || true)
MY_IP=$(echo "$IP_INFO" | grep -oE '"ip": *"[^"]+"' | cut -d'"' -f4)
COUNTRY=$(echo "$IP_INFO" | grep -oE '"country": *"[^"]+"' | cut -d'"' -f4)
[ -z "$MY_IP" ] && MY_IP=$(curl -s4m4 https://api.ipify.org || curl -s4m4 https://ifconfig.me)
[ -z "$COUNTRY" ] && COUNTRY="UNKNOWN"
SUBNET=$(echo "$MY_IP" | awk -F. '{print $1"."$2"."$3".0/24"}')

ARCH=$(uname -m)
if [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]]; then
    BIN_NAME="RealiTLScanner-linux-arm64"
else
    BIN_NAME="RealiTLScanner-linux-amd64"
fi

echo "=========================================================================="
echo "🚀 REALITY SNI 顶级优选引擎 | IP: $MY_IP ($COUNTRY) | 网段: $SUBNET"
echo "🛡️  运行模式: 内存沙盒零残留模式 (退出后自动粉碎一切临时文件与历史垃圾)"
echo "=========================================================================="

# 2. 在沙盒中下载对应架构的官方扫描器
echo "⏳ [1/3] 正在沙盒中加载 $BIN_NAME 扫描核心..."
wget -q -O "$WORK_DIR/scanner" "https://github.com/XTLS/RealiTLScanner/releases/latest/download/$BIN_NAME"
if [ ! -s "$WORK_DIR/scanner" ]; then
    echo "❌ 下载扫描核心失败，请检查 VPS 网络连接！"
    exit 1
fi
chmod +x "$WORK_DIR/scanner"

# 3. 扫描同网段 254 个邻居
echo "🔍 [2/3] 正在高速扫描 $SUBNET 网段内 254 个邻居 (约需 15~20 秒)..."
"$WORK_DIR/scanner" -addr "$SUBNET" -port 443 -thread 35 -timeout 4 -out "$WORK_DIR/result.csv" >/dev/null 2>&1

echo "🧪 [3/3] 正在并发执行【双国内DoH防墙校验 + 证书寿命 + H2握手测速】..."
echo "--------------------------------------------------------------------------"

RESULT_FILE="$WORK_DIR/verified.txt"
touch "$RESULT_FILE"

if [ -s "$WORK_DIR/result.csv" ]; then
    awk -F',' 'NR>1 {gsub(/"/, "", $6); gsub(/"/, "", $9); print $1, $5, $6, $9}' "$WORK_DIR/result.csv" | sort -u -k4,4 | while read -r ip curve cert_len domain; do
        (
            # 第1关：剔除泛域名、自签证书、CDN默认证书、被偷大厂域名及 30+ 种灰产/廉价后缀
            if [[ "$domain" =~ \*|localhost|Cloud[Ff]lare|Lucky|fastly|akamai|apple\.com|google\.com|microsoft\.com|127\.0\.0\.1|FIT2CLOUD|baota|1panel ]] || \
               [[ "$domain" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || \
               [[ "$domain" =~ \.(cn|gov|mil|edu|xyz|top|vip|lol|fun|work|sbs|mba|site|space|bond|cc|ink|navy|club|icu|ltd|online|cfd|cyou|pw|buzz|rest|monster|shop|asia|click|link|mom|party|pro|men|win|loan|bid|trade|date|review|stream|download|gdn|racing|jetzt|dpdns\.org)$ ]] || \
               [[ "$domain" =~ \.(go|lg)\.jp$ ]] || \
               [[ "$domain" =~ ^xn-- ]]; then
                exit 0
            fi

            # 证书链长度过短的直接剔除（排除伪造单证书）
            len_num=$(echo "$cert_len" | grep -oE '^[0-9]+' || echo 0)
            [ "$len_num" -lt 1500 ] && exit 0

            # 第2关：本机 DNS 正向核验（确保该域名真实指向该邻居 IP，排除同行假节点）
            resolved_ip=$(getent ahostsv4 "$domain" 2>/dev/null | awk '{print $1; exit}')
            [ "$resolved_ip" != "$ip" ] && exit 0

            # 第3关：中国大陆双 DoH (阿里 223.5.5.5 / 腾讯 1.12.12.12) 防污染与防墙核验
            cn_dns=$(curl -s -m 2 "https://223.5.5.5/resolve?name=${domain}&type=A" 2>/dev/null || curl -s -m 2 "https://1.12.12.12/resolve?name=${domain}&type=A" 2>/dev/null || true)
            if echo "$cn_dns" | grep -q '"Status":0'; then
                echo "$cn_dns" | grep -q "\"$ip\"" || exit 0
            fi

            # 第4关：实测 TLS 1.3 + HTTP/2 + 排除各大 CDN + 校验 HTTP 状态码 + 提取证书有效期与延迟
            check=$(curl -I -s -v -m 3 --connect-timeout 2 --tlsv1.3 -w "\nTIME_TLS:%{time_appconnect}\nHTTP_CODE:%{http_code}\n" "https://$domain" 2>&1)
            if echo "$check" | grep -q "TLSv1.3" && echo "$check" | grep -q "HTTP/2"; then
                if ! echo "$check" | grep -qiE "server: *(cloudflare|cloudfront|akamaighost|fastly|gws|ESF)"; then
                    # 排除 5xx 宕机状态码
                    http_code=$(echo "$check" | grep "^HTTP_CODE:" | cut -d: -f2)
                    [[ "$http_code" =~ ^5[0-9][0-9]$ || "$http_code" == "000" ]] && exit 0

                    # 计算证书剩余有效天数（剔除 < 15 天的快过期域名）
                    exp_str=$(echo "$check" | grep -i "expire date:" | sed 's/.*expire date: *//i' | tr -d '\r' | head -n1)
                    if [ -n "$exp_str" ]; then
                        exp_ts=$(date -d "$exp_str" +%s 2>/dev/null || echo 0)
                        now_ts=$(date +%s)
                        days_left=$(( (exp_ts - now_ts) / 86400 ))
                        [ "$days_left" -lt 15 ] && exit 0
                    else
                        days_left=60
                    fi

                    # 计算 TLS 握手耗时 (毫秒)
                    tls_sec=$(echo "$check" | grep "^TIME_TLS:" | cut -d: -f2)
                    tls_ms=$(awk -v t="$tls_sec" 'BEGIN { printf "%d", (t * 1000) }')
                    [ "$tls_ms" -le 0 ] && tls_ms=1

                    if [ "$curve" = "X25519MLKEM768" ]; then
                        echo "1|$tls_ms|$days_left|$domain|$ip|$curve|🌟 抗量子首选" >> "$RESULT_FILE"
                    else
                        echo "2|$tls_ms|$days_left|$domain|$ip|$curve|✅ 标准合格" >> "$RESULT_FILE"
                    fi
                fi
            fi
        ) &
    done
    wait
fi

# 4. 输出同网段优选结果或按国家自动匹配大站保底池
if [ -s "$RESULT_FILE" ]; then
    printf "%-16s | %-28s | %-15s | %-8s | %-10s | %s\n" "推荐等级" "可直接使用的 SNI 域名" "同网段邻居IP" "握手延迟" "证书有效期" "密钥交换曲线"
    echo "--------------------------------------------------------------------------"
    sort -t'|' -k1,1n -k2,2n -k3,3nr "$RESULT_FILE" | while IFS='|' read -r tier ms days dom dip dcurve label; do
        printf "%-18s | %-28s | %-15s | %-6s | %-8s | %s\n" "$label" "$dom" "$dip" "${ms}ms" "剩${days}天" "$dcurve"
    done
    BEST_DOM=$(sort -t'|' -k1,1n -k2,2n -k3,3nr "$RESULT_FILE" | head -n1 | cut -d'|' -f4)
else
    echo "⚠️ 当前 $SUBNET 网段内无满足严苛标准的邻居，已根据本机地区 ($COUNTRY) 启动大牌白名单测速..."
    case "$COUNTRY" in
        JP) POOL="www.iij.ad.jp www.sakura.ad.jp ftp.jaist.ac.jp www.nic.ad.jp addons.mozilla.org" ;;
        HK|TW|MO) POOL="ftp.cuhk.edu.hk www.hkix.net addons.mozilla.org swdist.apple.com dl.fedoraproject.org" ;;
        SG|KR|MY) POOL="addons.mozilla.org swdist.apple.com dl.fedoraproject.org aus5.mozilla.org" ;;
        DE|NL|FR|GB| EU) POOL="www.tu-berlin.de addons.mozilla.org dl.fedoraproject.org aus5.mozilla.org" ;;
        *) POOL="dl.fedoraproject.org addons.mozilla.org swdist.apple.com mirrors.mit.edu mirrors.ocf.berkeley.edu" ;;
    esac

    for bdom in $POOL; do
        (
            check=$(curl -I -s -v -m 3 --connect-timeout 2 --tlsv1.3 -w "\nTIME_TLS:%{time_appconnect}\n" "https://$bdom" 2>&1)
            if echo "$check" | grep -q "TLSv1.3" && echo "$check" | grep -q "HTTP/2"; then
                tls_sec=$(echo "$check" | grep "^TIME_TLS:" | cut -d: -f2)
                tls_ms=$(awk -v t="$tls_sec" 'BEGIN { printf "%d", (t * 1000) }')
                [ "$tls_ms" -le 0 ] && tls_ms=1
                echo "$tls_ms|$bdom" >> "$RESULT_FILE"
            fi
        ) &
    done
    wait
    sort -t'|' -k1,1n "$RESULT_FILE" | while IFS='|' read -r ms bdom; do
        echo "✅ [地区优选大站] 域名: $(printf '%-25s' "$bdom") (本机握手延迟: ${ms}ms)"
    done
    BEST_DOM=$(sort -t'|' -k1,1n "$RESULT_FILE" | head -n1 | cut -d'|' -f2)
fi

# 5. 自动生成当前节点专属的 X25519 公私钥对与 ShortId (方便在 V2board 中一键复制)
PRIV_KEY=""
PUB_KEY=""
if command -v openssl >/dev/null 2>&1; then
    PEM_FILE="$WORK_DIR/x25519.pem"
    if openssl genpkey -algorithm X25519 -out "$PEM_FILE" >/dev/null 2>&1; then
        PRIV_KEY=$(openssl pkey -in "$PEM_FILE" -outform DER 2>/dev/null | tail -c 32 | base64 | tr '+/' '-_' | tr -d '=\n')
        PUB_KEY=$(openssl pkey -in "$PEM_FILE" -pubout -outform DER 2>/dev/null | tail -c 32 | base64 | tr '+/' '-_' | tr -d '=\n')
    fi
fi
SHORT_ID=$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')

echo "=========================================================================="
echo "🏆 【V2board 节点安全性配置 — 一键复制套件】"
echo "--------------------------------------------------------------------------"
echo "  • Server Name(SNI) : $BEST_DOM"
echo "  • Server Port      : 443"
if [ -n "$PRIV_KEY" ] && [ -n "$PUB_KEY" ]; then
    echo "  • Private Key      : $PRIV_KEY"
    echo "  • Public Key       : $PUB_KEY"
fi
echo "  • ShortId          : $SHORT_ID"
echo "=========================================================================="
echo "🧹 沙盒自毁与历史垃圾清理已完成，当前 VPS 零文件残留！"
