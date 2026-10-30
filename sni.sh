#!/bin/bash
# ==============================================================================
# Project: REALITY SNI Ultimate Scanner & Validator (2026.10 Gold Edition)
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

# 创建独立内存沙盒目录，并注册退出自动销毁钩子 (先等待所有子进程结束再删目录)
WORK_DIR=$(mktemp -d /tmp/reality_sni_XXXXXX)
cleanup() {
    wait 2>/dev/null
    rm -rf "$WORK_DIR" 2>/dev/null
    clean_legacy_junk
}
trap cleanup EXIT INT TERM

# 提取证书剩余有效天数函数
get_cert_days() {
    local dom="$1"
    local check_out="$2"
    local exp_str=""
    exp_str=$(echo "$check_out" | grep -i "expire date:" | sed 's/.*expire date: *//i' | tr -d '\r' | head -n1)
    if [ -z "$exp_str" ] && command -v openssl >/dev/null 2>&1; then
        exp_str=$(echo | timeout 2 openssl s_client -servername "$dom" -connect "$dom:443" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2 | tr -d '\r')
    fi
    if [ -n "$exp_str" ]; then
        local exp_ts=$(date -d "$exp_str" +%s 2>/dev/null || echo 0)
        local now_ts=$(date +%s)
        if [ "$exp_ts" -gt "$now_ts" ]; then
            echo $(( (exp_ts - now_ts) / 86400 ))
            return
        fi
    fi
    echo 0
}

# 1. 自动获取本机公网 IP、网段前缀、所在国家及 CPU 架构
IP_INFO=$(curl -s4m4 https://ipinfo.io/json 2>/dev/null || true)
MY_IP=$(echo "$IP_INFO" | grep -oE '"ip": *"[^"]+"' | cut -d'"' -f4)
COUNTRY=$(echo "$IP_INFO" | grep -oE '"country": *"[^"]+"' | cut -d'"' -f4)
[ -z "$MY_IP" ] && MY_IP=$(curl -s4m4 https://api.ipify.org || curl -s4m4 https://ifconfig.me)
[ -z "$COUNTRY" ] && COUNTRY="UNKNOWN"
SUBNET_PREFIX=$(echo "$MY_IP" | awk -F. '{print $1"."$2"."$3"."}')
SUBNET="${SUBNET_PREFIX}0/24"

ARCH=$(uname -m)
if [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]]; then
    BIN_NAME="RealiTLScanner-linux-arm64"
else
    BIN_NAME="RealiTLScanner-linux-amd64"
fi

echo "===================================================================================================="
echo "🚀 REALITY SNI 顶级优选引擎 (2026.10 严选版) | 本机IP: $MY_IP ($COUNTRY) | 网段: $SUBNET"
echo "🛡️  运行模式: 内存沙盒零残留模式 (主流后缀白名单 + 纯TLS握手测速 + HTTP状态验真)"
echo "===================================================================================================="

# 2. 在沙盒中下载对应架构的官方扫描器
echo "⏳ [1/3] 正在内存沙盒中加载 $BIN_NAME 扫描核心..."
wget -q -O "$WORK_DIR/scanner" "https://github.com/XTLS/RealiTLScanner/releases/latest/download/$BIN_NAME"
if [ ! -s "$WORK_DIR/scanner" ]; then
    echo "❌ 下载扫描核心失败，请检查 VPS 网络连接！"
    exit 1
fi
chmod +x "$WORK_DIR/scanner"

# 3. 扫描同网段 254 个邻居
echo "🔍 [2/3] 正在高速扫描 $SUBNET 网段内 254 个邻居 (约需 15~20 秒)..."
"$WORK_DIR/scanner" -addr "$SUBNET" -port 443 -thread 35 -timeout 4 -out "$WORK_DIR/result.csv" >/dev/null 2>&1

echo "🧪 [3/3] 正在并发执行【主流后缀白名单 + 同网段DNS验真 + 纯握手延迟 + 200状态码验真】..."
echo "----------------------------------------------------------------------------------------------------"

RESULT_FILE="$WORK_DIR/verified.txt"
touch "$RESULT_FILE"

if [ -s "$WORK_DIR/result.csv" ]; then
    # 预处理候选列表到临时文件，避免管道符 | 导致 while 循环进入子进程使 wait 失效
    CANDIDATES_FILE="$WORK_DIR/candidates.txt"
    awk -F',' 'NR>1 {
        gsub(/"/, "", $0);
        len = $6;
        sub(/\(.*/, "", len);
        print $1 "|" $5 "|" len "|" $9
    }' "$WORK_DIR/result.csv" | sort -t'|' -u -k4,4 > "$CANDIDATES_FILE"

    while IFS='|' read -r ip curve cert_len domain; do
        # 控制最大并发数为 12，防止瞬间塞爆 DNS 与网卡导致延迟虚高
        while [ "$(jobs -rp | wc -l)" -ge 12 ]; do
            sleep 0.1
        done

        (
            # 排除本机自身 IP
            [ "$ip" == "$MY_IP" ] && exit 0

            # 第1关：剔除泛域名(*)、自签证书、CDN默认证书、被偷大厂域名
            if [[ "$domain" =~ \*|localhost|Cloud[Ff]lare|Lucky|fastly|akamai|apple\.com|google\.com|microsoft\.com|127\.0\.0\.1|FIT2CLOUD|baota|1panel ]] || \
               [[ "$domain" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || \
               [[ "$domain" =~ ^xn-- ]]; then
                exit 0
            fi

            # 第2关：【严格主流后缀白名单】只允许正规商业/机构后缀 (.com/.net/.org 及地区正规后缀)，一刀切淘汰 .world/.xyz/.top/.cn 等奇葩后缀
            if ! [[ "$domain" =~ \.(com|net|org|co\.jp|ad\.jp|or\.jp|ac\.jp|ne\.jp|com\.hk|org\.hk|edu\.hk|com\.sg|com\.tw|de|co\.uk|org\.uk|nl|fr|ch|se|io|ai|dev|app)$ ]]; then
                exit 0
            fi

            # 第3关：剔除数字开头的临时子域名 (如 2026.xxx.com) 及明显是后台/接口/节点的子域名
            if [[ "$domain" =~ ^[0-9]+\. ]] || [[ "$domain" =~ ^(api|bot|pay|admin|panel|node|v2|clash|sub|test|tests|dev|mail|smtp|pop|imap|oa|erp|crm|git|alist|kefu|cuishou)\. ]]; then
                exit 0
            fi

            # 证书链长度校验（排除伪造单证书）
            [[ ! "$cert_len" =~ ^[0-9]+$ ]] && cert_len=2000
            [ "$cert_len" -lt 1800 ] && exit 0

            # 第4关：实测真实 DNS 解析与 TLS 1.3 + HTTP/2 握手（同时采集 DNS耗时 与 TLS总耗时）
            check=$(curl -I -s -v -m 4 --connect-timeout 2 --tlsv1.3 -w "\nREMOTE_IP:%{remote_ip}\nTIME_DNS:%{time_namelookup}\nTIME_TLS:%{time_appconnect}\nHTTP_CODE:%{http_code}\n" "https://$domain" 2>&1)

            # 验证该域名真实 DNS 解析出的 IP 必须属于当前同一个 /24 网段（剔除同行假节点或套了 CF 的站）
            remote_ip=$(echo "$check" | grep "^REMOTE_IP:" | cut -d: -f2 | tr -d '\r ')
            [[ "$remote_ip" != "${SUBNET_PREFIX}"* ]] && exit 0

            # 验证 TLS 1.3 + HTTP/2 + 非大型泛播 CDN
            if echo "$check" | grep -q "TLSv1.3" && echo "$check" | grep -qE "HTTP/2|ALPN: server accepted h2"; then
                if ! echo "$check" | grep -qiE "server: *(cloudflare|cloudfront|akamaighost|fastly|gws|ESF)"; then
                    # 提取 HTTP 状态码，淘汰 5xx/000 异常站点
                    http_code=$(echo "$check" | grep "^HTTP_CODE:" | cut -d: -f2 | tr -d '\r ')
                    [[ "$http_code" =~ ^5[0-9][0-9]$ || "$http_code" == "000" ]] && exit 0

                    # 第5关：中国大陆 DoH (223.5.5.5) 防污染校验
                    cn_dns=$(curl -s -m 2 "https://223.5.5.5/resolve?name=${domain}&type=A" 2>/dev/null || true)
                    if echo "$cn_dns" | grep -q '"Status":0' && echo "$cn_dns" | grep -q '"data"'; then
                        echo "$cn_dns" | grep -q "$SUBNET_PREFIX" || exit 0
                    fi

                    # 第6关：计算证书剩余天数（剔除 < 15 天的快过期域名）
                    days_left=$(get_cert_days "$domain" "$check")
                    [ "$days_left" -lt 15 ] && exit 0

                    # 第7关：计算扣除首次 DNS 查询耗时后的【纯正 TCP+TLS 握手延迟 (毫秒)】
                    dns_sec=$(echo "$check" | grep "^TIME_DNS:" | cut -d: -f2 | tr -d '\r ')
                    tls_sec=$(echo "$check" | grep "^TIME_TLS:" | cut -d: -f2 | tr -d '\r ')
                    tls_ms=$(awk -v t="$tls_sec" -v d="$dns_sec" 'BEGIN { ms = int((t - d) * 1000 + 0.5); if (ms <= 0) ms = 1; print ms }')

                    # 第8关：100分制严苛抗封评分
                    score=45 # 同网段真邻居基础分 45 (ASN与IP段100%吻合)

                    # 曲线加分 (最高 +15)
                    if [ "$curve" == "X25519MLKEM768" ]; then
                        score=$((score + 15))
                        label="🌟 抗量子同网段"
                    else
                        score=$((score + 8))
                        label="✅ 标准同网段"
                    fi

                    # 纯握手延迟加分 (最高 +15)
                    if [ "$tls_ms" -le 5 ]; then
                        score=$((score + 15))
                    elif [ "$tls_ms" -le 15 ]; then
                        score=$((score + 12))
                    elif [ "$tls_ms" -le 30 ]; then
                        score=$((score + 8))
                    fi

                    # HTTP 状态码加分：直接返回 200 OK 的真实网页大幅加分 (+15)，避免使用 301/302 跳转域名
                    if [ "$http_code" == "200" ]; then
                        score=$((score + 15))
                        status_tag="200直达"
                    elif [[ "$http_code" =~ ^30[1278]$ ]]; then
                        score=$((score + 3))
                        status_tag="${http_code}跳转"
                    else
                        score=$((score + 6))
                        status_tag="HTTP-${http_code}"
                    fi

                    # 域名形态与证书健康加分：带 www. 的正规门户且证书长效 (+10)
                    if [[ "$domain" =~ ^www\. ]] && [ "$days_left" -ge 30 ]; then
                        score=$((score + 10))
                    elif [ "$days_left" -ge 45 ]; then
                        score=$((score + 6))
                    else
                        score=$((score + 3))
                    fi

                    echo "$score|$tls_ms|$days_left|$domain|$remote_ip|$curve|$status_tag|$label" >> "$RESULT_FILE"
                fi
            fi
        ) &
    done < "$CANDIDATES_FILE"
    # 此时 wait 在主 Shell 中运行，100% 等待所有子进程全部完成！
    wait
fi

# 4. 仅当同网段真的一个合格邻居都没有时，才启动同地区非烂大街的学术/运营商源站测速
if [ ! -s "$RESULT_FILE" ]; then
    echo "⚠️ 当前 $SUBNET 网段内无满足白名单标准的邻居，正在测速本地区 ($COUNTRY) 学术/运营商源站..."
    case "$COUNTRY" in
        JP) POOL="www.iij.ad.jp www.sakura.ad.jp ftp.jaist.ac.jp www.nic.ad.jp www.wide.ad.jp" ;;
        HK|TW|MO) POOL="www.hkix.net www.cuhk.edu.hk www.hku.hk www.ust.hk ftp.jaist.ac.jp" ;;
        SG|KR|MY) POOL="www.nus.edu.sg www.ntu.edu.sg ftp.jaist.ac.jp www.iij.ad.jp" ;;
        DE|NL|FR|GB|EU) POOL="www.tu-berlin.de www.uni-heidelberg.de www.ethz.ch www.epfl.ch" ;;
        *) POOL="mirrors.mit.edu mirrors.ocf.berkeley.edu www.stanford.edu www.princeton.edu" ;;
    esac

    for bdom in $POOL; do
        (
            check=$(curl -I -s -v -m 4 --connect-timeout 2 --tlsv1.3 -w "\nREMOTE_IP:%{remote_ip}\nTIME_DNS:%{time_namelookup}\nTIME_TLS:%{time_appconnect}\nHTTP_CODE:%{http_code}\n" "https://$bdom" 2>&1)
            if echo "$check" | grep -q "TLSv1.3" && echo "$check" | grep -qE "HTTP/2|ALPN: server accepted h2"; then
                if ! echo "$check" | grep -qiE "server: *(cloudflare|cloudfront|akamaighost|fastly)"; then
                    remote_ip=$(echo "$check" | grep "^REMOTE_IP:" | cut -d: -f2 | tr -d '\r ')
                    dns_sec=$(echo "$check" | grep "^TIME_DNS:" | cut -d: -f2 | tr -d '\r ')
                    tls_sec=$(echo "$check" | grep "^TIME_TLS:" | cut -d: -f2 | tr -d '\r ')
                    tls_ms=$(awk -v t="$tls_sec" -v d="$dns_sec" 'BEGIN { ms = int((t - d) * 1000 + 0.5); if (ms <= 0) ms = 1; print ms }')
                    http_code=$(echo "$check" | grep "^HTTP_CODE:" | cut -d: -f2 | tr -d '\r ')
                    days_left=$(get_cert_days "$bdom" "$check")
                    [ "$days_left" -le 0 ] && days_left=60
                    curve="X25519"
                    echo "$check" | grep -qi "MLKEM768" && curve="X25519MLKEM768"
                    score=$(( 65 - (tls_ms / 2) ))
                    [ "$score" -lt 15 ] && score=15
                    echo "$score|$tls_ms|$days_left|$bdom|$remote_ip|$curve|HTTP-${http_code}|🛡️ 地区低延大站" >> "$RESULT_FILE"
                fi
            fi
        ) &
    done
    wait
fi

# 5. 打印完整排行榜表格
printf "%-18s | %-6s | %-26s | %-15s | %-6s | %-8s | %-8s | %s\n" "推荐等级" "评分" "可直接使用的 SNI 域名" "目标IP地址" "纯延迟" "网页状态" "证书寿命" "密钥曲线"
echo "----------------------------------------------------------------------------------------------------"
sort -t'|' -k1,1nr -k2,2n -k3,3nr "$RESULT_FILE" | while IFS='|' read -r score ms days dom dip dcurve st_tag label; do
    printf "%-20s | %-6s | %-26s | %-15s | %-6s | %-8s | %-8s | %s\n" "$label" "${score}分" "$dom" "$dip" "${ms}ms" "$st_tag" "剩${days}天" "$dcurve"
done

BEST_LINE=$(sort -t'|' -k1,1nr -k2,2n -k3,3nr "$RESULT_FILE" | head -n1)
BEST_SCORE=$(echo "$BEST_LINE" | cut -d'|' -f1)
BEST_MS=$(echo "$BEST_LINE" | cut -d'|' -f2)
BEST_DAYS=$(echo "$BEST_LINE" | cut -d'|' -f3)
BEST_DOM=$(echo "$BEST_LINE" | cut -d'|' -f4)
BEST_CURVE=$(echo "$BEST_LINE" | cut -d'|' -f6)
BEST_ST=$(echo "$BEST_LINE" | cut -d'|' -f7)

# 6. 自动生成当前节点专属的 X25519 公私钥对与 ShortId
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

echo "===================================================================================================="
echo "🏆 【V2board 节点安全性配置 — 冠军推荐一键复制套件】"
echo "----------------------------------------------------------------------------------------------------"
echo "  • Server Name(SNI) : $BEST_DOM   (评分: ${BEST_SCORE}分 | 纯握手延迟: ${BEST_MS}ms | 状态: $BEST_ST | 证书剩余: ${BEST_DAYS}天 | 曲线: $BEST_CURVE)"
echo "  • Server Port      : 443"
if [ -n "$PRIV_KEY" ] && [ -n "$PUB_KEY" ]; then
    echo "  • Private Key      : $PRIV_KEY"
    echo "  • Public Key       : $PUB_KEY"
fi
echo "  • ShortId          : $SHORT_ID"
echo "===================================================================================================="
echo "🧹 沙盒自毁与历史垃圾清理已完成，当前 VPS 零文件残留！"
