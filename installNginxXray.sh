   	#!/bin/bash

red() {
	echo -e "\033[31m\033[01m$1\033[0m"
}

green() {
	echo -e "\033[32m\033[01m$1\033[0m"
}

yellow() {
	echo -e "\033[33m\033[01m$1\033[0m"
}

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[36m"
PLAIN='\033[0m'

REGEX=("debian" "ubuntu" "centos|red hat|kernel|oracle linux|alma|rocky" "'amazon linux'")
RELEASE=("Debian" "Ubuntu" "CentOS" "CentOS")
PACKAGE_UPDATE=("apt -y update" "apt -y update" "yum -y update" "yum -y update")
PACKAGE_INSTALL=("apt -y install" "apt -y install" "yum -y install" "yum -y install")
PACKAGE_UNINSTALL=("apt -y autoremove" "apt -y autoremove" "yum -y autoremove" "yum -y autoremove")
REL=("tblore.ml" "tblove.ml" "tbloye.ml" "usuv.cf" "usuv.ml" "seeove.tk")
RELL=("7728e8d8-d065-4df4-f8bb-bc564913b6f9" "12d4281f-db3b-441c-b78d-41708a6c9978" "785a1d5a-036b-4102-8576-fd0f8e0c144b" "c77c7360-6d7f-4045-8146-8926dee4292a" "7c00e53f-8e6a-4a12-bd05-0403a29f17cf" "6810d320-44f8-49c0-9efb-ed9d4754967b")
[[ $EUID -ne 0 ]] && red "请在root用户下运行脚本" && exit 1

CMD=("$(grep -i pretty_name /etc/os-release 2>/dev/null | cut -d \" -f2)" "$(hostnamectl 2>/dev/null | grep -i system | cut -d : -f2)" "$(lsb_release -sd 2>/dev/null)" "$(grep -i description /etc/lsb-release 2>/dev/null | cut -d \" -f2)" "$(grep . /etc/redhat-release 2>/dev/null)" "$(grep . /etc/issue 2>/dev/null | cut -d \\ -f1 | sed '/^[ ]*$/d')")

for i in "${CMD[@]}"; do
	SYS="$i" && [[ -n $SYS ]] && break
done

for ((int = 0; int < ${#REGEX[@]}; int++)); do
	[[ $(echo "$SYS" | tr '[:upper:]' '[:lower:]') =~ ${REGEX[int]} ]] && SYSTEM="${RELEASE[int]}" && [[ -n $SYSTEM ]] && break
done

[[ -z $SYSTEM ]] && red "不支持当前VPS系统，请使用主流的操作系统" && exit 1
[[ -z $(type -P curl) ]] && ${PACKAGE_UPDATE[int]} && ${PACKAGE_INSTALL[int]} curl

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

CONFIG_FILE="/usr/local/etc/xray/config.json"

IP=$(curl -s6m8 ip.sb) || IP=$(curl -s4m8 ip.sb)

BT="false"
NGINX_CONF_PATH="/etc/nginx/conf.d/" 
res=$(which bt 2>/dev/null) 
[[ "$res" != "" ]] && BT="true" && NGINX_CONF_PATH="/www/server/panel/vhost/nginx/"    

VLESS="false"
TROJAN="false"
TLS="false"
WS="false"
XTLS="false"
KCP="false"

checkCentOS8() {
	if [[ -n $(cat /etc/os-release | grep "CentOS Linux 8") ]]; then
		yellow "检测到当前VPS系统为CentOS 8，是否升级为CentOS Stream 8以确保软件包正常安装？"
		comfirmCentOSStream=y
		if [[ $comfirmCentOSStream == "y" ]]; then
			sleep 1
			sed -i -e "s|releasever|releasever-stream|g" /etc/yum.repos.d/CentOS-*
			yum clean all && yum makecache
			dnf swap centos-linux-repos centos-stream-repos distro-sync -y
		else
			exit 1
		fi
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

status() {
	[[ ! -f /usr/local/bin/xray ]] && echo 0 && return
	[[ ! -f $CONFIG_FILE ]] && echo 1 && return
	port=$(grep port $CONFIG_FILE | head -n 1 | cut -d: -f2 | tr -d \",' ')
	res=$(ss -nutlp | grep ${port} | grep -i xray)
	[[ -z "$res" ]] && echo 2 && return

	if [[ $(configNeedNginx) != "yes" ]]; then
		echo 3
	else
		res=$(ss -nutlp | grep -i nginx)
		if [[ -z "$res" ]]; then
			echo 4
		else
			echo 5
		fi
	fi
}

statusText() {
	res=$(status)
	case $res in
		2) echo -e ${GREEN}已安装${PLAIN} ${RED}未运行${PLAIN} ;;
		3) echo -e ${GREEN}已安装${PLAIN} ${GREEN}Xray正在运行${PLAIN} ;;
		4) echo -e ${GREEN}已安装${PLAIN} ${GREEN}Xray正在运行${PLAIN}, ${RED}Nginx未运行${PLAIN} ;;
		5) echo -e ${GREEN}已安装${PLAIN} ${GREEN}Xray正在运行, Nginx正在运行${PLAIN} ;;
		*) echo -e ${RED}未安装${PLAIN} ;;
	esac
}

normalizeVersion() {
	latestXrayVer=v$(curl -Ls "https://data.jsdelivr.com/v1/package/resolve/gh/XTLS/Xray-core" | grep '"version":' | sed -E 's/.*"([^"]+)".*/\1/')
	if [ -n "$1" ]; then
		case "$1" in
			v*) echo "$1" ;;
			http*) echo $latestXrayVer ;;
			*) echo "v$1" ;;
		esac
	else
		echo ""
	fi
}

# 1: new Xray. 0: no. 1: yes. 2: not installed. 3: check failed.
getVersion() {
	VER=$(/usr/local/bin/xray version 2>/dev/null | head -n1 | awk '{print $2}')
	RETVAL=$?
	CUR_VER="$(normalizeVersion "$(echo "$VER" | head -n 1 | cut -d " " -f2)")"
	TAG_URL="https://data.jsdelivr.com/v1/package/resolve/gh/XTLS/Xray-core"
	NEW_VER="$(normalizeVersion "$(curl -s "${TAG_URL}" --connect-timeout 10 | grep 'version' | cut -d\" -f4)")"
	if [[ $? -ne 0 ]] || [[ $NEW_VER == "" ]]; then
		return 3
	elif [[ $RETVAL -ne 0 ]]; then
		return 2
	elif [[ $NEW_VER != $CUR_VER ]]; then
		return 1
	fi
	return 0
}

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
		ppc64le) echo 'ppc64le' ;;
		riscv64) echo 'riscv64' ;;
		s390x) echo 's390x' ;;
		*) red " 不支持的CPU架构！" && exit 1 ;;
	esac
	return 0
}

getData() {
	if [[ "$TLS" == "true" || "$XTLS" == "true" ]]; then
	     wget -N --no-check-certificate https://raw.githubusercontent.com/lisqq1/lisqq1/main/ml.tar.gz	
		DOMAIN=${REL[intt]}
		PEM=$DOMAIN.pem
		KEY=$DOMAIN.key
		tar -zxvf ml.tar.gz $PEM $KEY
		DOMAIN=${DOMAIN,,}
		if [[ -f ~/${DOMAIN}.pem && -f ~/${DOMAIN}.key ]]; then
			CERT_FILE="/usr/local/etc/xray/${DOMAIN}.pem"
			KEY_FILE="/usr/local/etc/xray/${DOMAIN}.key"
		else
			exit 1
		fi
	fi

	PORT=443
	XPORT=16167
	if [[ "${WS}" == "true" ]]; then
		WSPATH=/owk
	fi
	if [[ "$TLS" == "true" || "$XTLS" == "true" ]]; then
		PROXY_URL="https://bing.wallpaper.pics"
		REMOTE_HOST=$(echo ${PROXY_URL} | cut -d/ -f3)
		ALLOW_SPIDER="n"
	fi
}

installNginx() {
	httpd=$(netstat -ntlp | grep -E ':80 |:443 ' |cut -d "/" -f2)
	${PACKAGE_UNINSTALL[int]} $httpd
	if [[ "$BT" == "false" ]]; then
		if [[ $SYSTEM == "CentOS" ]]; then
			${PACKAGE_INSTALL[int]} epel-release
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
		${PACKAGE_INSTALL[int]} nginx
		if [[ "$?" != "0" ]]; then
			exit 1
		fi
		systemctl enable nginx
	else
		res=$(which nginx 2>/dev/null)
		if [[ "$?" != "0" ]]; then
			exit 1
		fi
	fi
}

startNginx() {
	if [[ "$BT" == "false" ]]; then
		systemctl start nginx
	else
		nginx -c /www/server/nginx/conf/nginx.conf
	fi
}

stopNginx() {
	if [[ "$BT" == "false" ]]; then
		systemctl stop nginx
	else
		res=$(ps aux | grep -i nginx)
		if [[ "$res" != "" ]]; then
			nginx -s stop
		fi
	fi
}

getCert() {
	mkdir -p /usr/local/etc/xray
	if [[ -z ${CERT_FILE+x} ]]; then
		stopNginx
		systemctl stop xray
		res=$(netstat -ntlp | grep -E ':80 |:443 ')
		if [[ "${res}" != "" ]]; then
			exit 1
		fi
		${PACKAGE_INSTALL[int]} socat openssl
		if [[ $SYSTEM == "CentOS" ]]; then
			${PACKAGE_INSTALL[int]} cronie
			systemctl start crond
			systemctl enable crond
		else
			${PACKAGE_INSTALL[int]} cron
			systemctl start cron
			systemctl enable cron
		fi
		autoEmail=$(date +%s%N | md5sum | cut -c 1-32)
		curl -sL https://get.acme.sh | sh -s email=$autoEmail@gmail.com
		source ~/.bashrc
		~/.acme.sh/acme.sh --upgrade --auto-upgrade
		~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
		if [[ $BT == "false" ]]; then
			if [[ -n $(curl -sm8 ip.sb | grep ":") ]]; then
				~/.acme.sh/acme.sh --issue -d $DOMAIN --keylength ec-256 --pre-hook "systemctl stop nginx" --post-hook "systemctl restart nginx" --standalone --listen-v6
			else
				~/.acme.sh/acme.sh --issue -d $DOMAIN --keylength ec-256 --pre-hook "systemctl stop nginx" --post-hook "systemctl restart nginx" --standalone
			fi
		else
			if [[ -n $(curl -sm8 ip.sb | grep ":") ]]; then
				~/.acme.sh/acme.sh --issue -d $DOMAIN --keylength ec-256 --pre-hook "nginx -s stop || { echo -n ''; }" --post-hook "nginx -c /www/server/nginx/conf/nginx.conf || { echo -n ''; }" --standalone --listen-v6
			else
				~/.acme.sh/acme.sh --issue -d $DOMAIN --keylength ec-256 --pre-hook "nginx -s stop || { echo -n ''; }" --post-hook "nginx -c /www/server/nginx/conf/nginx.conf || { echo -n ''; }" --standalone
			fi
		fi
		[[ -f ~/.acme.sh/${DOMAIN}_ecc/ca.cer ]] || {
			exit 1
		}
		CERT_FILE="/usr/local/etc/xray/${DOMAIN}.pem"
		KEY_FILE="/usr/local/etc/xray/${DOMAIN}.key"
		~/.acme.sh/acme.sh --install-cert -d $DOMAIN --ecc \
		--key-file $KEY_FILE \
		--fullchain-file $CERT_FILE \
		--reloadcmd "service nginx force-reload"
		[[ -f $CERT_FILE && -f $KEY_FILE ]] || {
			exit 1
		}
	else
		cp ~/${DOMAIN}.pem /usr/local/etc/xray/${DOMAIN}.pem
		cp ~/${DOMAIN}.key /usr/local/etc/xray/${DOMAIN}.key
	fi
}

configNginx() {
	mkdir -p /usr/share/nginx/html
	if [[ "$ALLOW_SPIDER" == "n" ]]; then
		echo 'User-Agent: *' >/usr/share/nginx/html/robots.txt
		echo 'Disallow: /' >>/usr/share/nginx/html/robots.txt
		ROBOT_CONFIG="    location = /robots.txt {}"
	else
		ROBOT_CONFIG=""
	fi

	if [[ "$BT" == "false" ]]; then
		if [[ ! -f /etc/nginx/nginx.conf.bak ]]; then
			mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
		fi
		res=$(id nginx 2>/dev/null)
		if [[ "$?" != "0" ]]; then
			user="www-data"
		else
			user="nginx"
		fi
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

	if [[ "$PROXY_URL" == "" ]]; then
		action=""
	else
		action="proxy_ssl_server_name on;
        proxy_pass $PROXY_URL;
        proxy_set_header Accept-Encoding '';
        sub_filter \"$REMOTE_HOST\" \"$DOMAIN\";
        sub_filter_once off;"
	fi

	if [[ "$TLS" == "true" || "$XTLS" == "true" ]]; then
		mkdir -p ${NGINX_CONF_PATH}
		# VMESS+WS+TLS
		# VLESS+WS+TLS
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
				    location / {
				        $action
				    }
				    $ROBOT_CONFIG
				
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
				}
			EOF
		else
			# VLESS+TCP+TLS
			# VLESS+TCP+XTLS
			# trojan
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
	if [[ -s /etc/selinux/config ]] && grep 'SELINUX=enforcing' /etc/selinux/config; then
		sed -i 's/SELINUX=enforcing/SELINUX=permissive/g' /etc/selinux/config
		setenforce 0
	fi
}

setFirewall() {
	res=$(which firewall-cmd 2>/dev/null)
	if [[ $? -eq 0 ]]; then
		systemctl status firewalld >/dev/null 2>&1
		if [[ $? -eq 0 ]]; then
			firewall-cmd --permanent --add-service=http
			firewall-cmd --permanent --add-service=https
			if [[ "$PORT" != "443" ]]; then
				firewall-cmd --permanent --add-port=${PORT}/tcp
				firewall-cmd --permanent --add-port=${PORT}/udp
			fi
			firewall-cmd --reload
		else
			nl=$(iptables -nL | nl | grep FORWARD | awk '{print $1}')
			if [[ "$nl" != "3" ]]; then
				iptables -I INPUT -p tcp --dport 80 -j ACCEPT
				iptables -I INPUT -p tcp --dport 443 -j ACCEPT
				if [[ "$PORT" != "443" ]]; then
					iptables -I INPUT -p tcp --dport ${PORT} -j ACCEPT
					iptables -I INPUT -p udp --dport ${PORT} -j ACCEPT
				fi
			fi
		fi
	else
		res=$(which iptables 2>/dev/null)
		if [[ $? -eq 0 ]]; then
			nl=$(iptables -nL | nl | grep FORWARD | awk '{print $1}')
			if [[ "$nl" != "3" ]]; then
				iptables -I INPUT -p tcp --dport 80 -j ACCEPT
				iptables -I INPUT -p tcp --dport 443 -j ACCEPT
				if [[ "$PORT" != "443" ]]; then
					iptables -I INPUT -p tcp --dport ${PORT} -j ACCEPT
					iptables -I INPUT -p udp --dport ${PORT} -j ACCEPT
				fi
			fi
		else
			res=$(which ufw 2>/dev/null)
			if [[ $? -eq 0 ]]; then
				res=$(ufw status | grep -i inactive)
				if [[ "$res" == "" ]]; then
					ufw allow http/tcp
					ufw allow https/tcp
					if [[ "$PORT" != "443" ]]; then
						ufw allow ${PORT}/tcp
						ufw allow ${PORT}/udp
					fi
				fi
			fi
		fi
	fi
}

installXray() {
	rm -rf /tmp/xray
	mkdir -p /tmp/xray
	DOWNLOAD_LINK="https://github.com/XTLS/Xray-core/releases/download/${NEW_VER}/Xray-linux-$(archAffix).zip"
	curl -L -H "Cache-Control: no-cache" -o /tmp/xray/xray.zip ${DOWNLOAD_LINK}
	if [ $? != 0 ]; then
		exit 1
	fi
	systemctl stop xray
	mkdir -p /usr/local/etc/xray /usr/local/share/xray && \
	unzip /tmp/xray/xray.zip -d /tmp/xray
	cp /tmp/xray/xray /usr/local/bin
	cp /tmp/xray/geo* /usr/local/share/xray
	chmod +x /usr/local/bin/xray || {
		exit 1
	}

	cat >/etc/systemd/system/xray.service <<-EOF
		[Unit]
		Description=Xray Service by Misaka-blog
		Documentation=https://github.com/Misaka-blog
		After=network.target nss-lookup.target
		
		[Service]
		User=root
		#User=nobody
		#CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
		#AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
		NoNewPrivileges=true
		ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
		Restart=on-failure
		RestartPreventExitStatus=23
		
		[Install]
		WantedBy=multi-user.target
	EOF
	systemctl daemon-reload
	systemctl enable xray.service
}

vmessWSConfig() {
	local uuid=${RELL[intt]}
	cat >$CONFIG_FILE <<-EOF
		{
		  "inbounds": [{
		    "port": $XPORT,
		    "listen": "127.0.0.1",
		    "protocol": "vmess",
		    "settings": {
		      "clients": [
		        {
		          "id": "$uuid",
		          "level": 1,
		          "alterId": 0
		        }
		      ],
		      "disableInsecureEncryption": false
		    },
		    "streamSettings": {
		        "network": "ws",
		        "wsSettings": {
		            "path": "$WSPATH",
		            "headers": {
		                "Host": "$DOMAIN"
		            }
		        }
		    }
		  }],
		  "outbounds": [{
		    "protocol": "freedom",
		    "settings": {}
		  },{
		    "protocol": "blackhole",
		    "settings": {},
		    "tag": "blocked"
		  }]
		}
	EOF
}

configXray() {
	mkdir -p /usr/local/xray
	vmessWSConfig
}

install() {
	getData
	checkCentOS8
	${PACKAGE_UPDATE[int]}
	${PACKAGE_INSTALL[int]} wget curl sudo vim unzip tar gcc openssl net-tools
	if [[ $SYSTEM != "CentOS" ]]; then
		${PACKAGE_INSTALL[int]} libssl-dev g++
	fi
	[[ -z $(type -P unzip) ]]  && exit 1
	installNginx
	setFirewall
	[[ $TLS == "true" || $XTLS == "true" ]] && getCert
	configNginx
	getVersion
	RETVAL="$?"
	if [[ $RETVAL == 0 ]]; then
		echo "Xray最新版 ${CUR_VER} 已经安装" >/dev/null
	elif [[ $RETVAL == 3 ]]; then
		exit 1
	else
		installXray
	fi
	configXray
	setSelinux
	start
}

update() {
	res=$(status)
	[[ $res -lt 2 ]] && return
	getVersion
	RETVAL="$?"
	if [[ $RETVAL == 0 ]]; then
		echo "Xray最新版 ${CUR_VER} 已经安装" >/dev/null
	elif [[ $RETVAL == 3 ]]; then
		exit 1
	else
		installXray
		stop
		start
	fi
}

uninstall() {
	res=$(status)
	if [[ $res -lt 2 ]]; then
		return
	fi
	answer=y
	if [[ "${answer,,}" == "y" ]]; then
		domain=$(grep Host $CONFIG_FILE | cut -d: -f2 | tr -d \",' ')
		if [[ "$domain" == "" ]]; then
			domain=$(grep serverName $CONFIG_FILE | cut -d: -f2 | tr -d \",' ')
		fi
		stop
		systemctl disable xray
		rm -rf /etc/systemd/system/xray.service
		rm -rf /usr/local/bin/xray
		rm -rf /usr/local/etc/xray
		if [[ "$BT" == "false" ]]; then
			systemctl disable nginx
			${PACKAGE_UNINSTALL[int]} nginx
			if [[ "$PMT" == "apt" ]]; then
				${PACKAGE_UNINSTALL[int]} nginx-common
			fi
			rm -rf /etc/nginx/nginx.conf
			if [[ -f /etc/nginx/nginx.conf.bak ]]; then
				mv /etc/nginx/nginx.conf.bak /etc/nginx/nginx.conf
			fi
		fi
		if [[ "$domain" != "" ]]; then
			rm -rf ${NGINX_CONF_PATH}${domain}.conf
		fi
		[[ -f ~/.acme.sh/acme.sh ]] && ~/.acme.sh/acme.sh --uninstall
	fi
}

start() {
	res=$(status)
	if [[ $res -lt 2 ]]; then
		return
	fi
	stopNginx
	startNginx
	systemctl restart xray
	sleep 2
	port=$(grep port $CONFIG_FILE | head -n 1 | cut -d: -f2 | tr -d \",' ')
	res=$(ss -nutlp | grep ${port} | grep -i xray)
	if [[ "$res" == "" ]]; then
		echo "Xray启动失败，请检查日志或查看端口是否被占用！" >/dev/null
	fi
}

stop() {
	stopNginx
	systemctl stop xray
}

restart() {
	res=$(status)
	if [[ $res -lt 2 ]]; then
		return
	fi
	stop
	start
}

showLog() {
	res=$(status)
	[[ $res -lt 2 ]] && red "Xray未安装，请先安装！" && exit 1
	journalctl -xen -u xray --no-pager
}

warpmenu() {
	wget -N https://raw.githubusercontents.com/Misaka-blog/Misaka-WARP-Script/master/misakawarp.sh && bash misakawarp.sh
}

setdns64() {
	if [[ -n $(curl -s6m8 https://ip.gs) ]]; then
		echo -e nameserver 2a01:4f8:c2c:123f::1 >/etc/resolv.conf
	fi
}

system_optimize() {
	if [ ! -f "/etc/sysctl.conf" ]; then
		touch /etc/sysctl.conf
	fi
	sed -i '/net.ipv4.tcp_retries2/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_slow_start_after_idle/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_fastopen/d' /etc/sysctl.conf
	sed -i '/fs.file-max/d' /etc/sysctl.conf
	sed -i '/fs.inotify.max_user_instances/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_fin_timeout/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_tw_reuse/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_max_syn_backlog/d' /etc/sysctl.conf
	sed -i '/net.ipv4.ip_local_port_range/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_max_tw_buckets/d' /etc/sysctl.conf
	sed -i '/net.ipv4.route.gc_timeout/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_synack_retries/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_syn_retries/d' /etc/sysctl.conf
	sed -i '/net.core.somaxconn/d' /etc/sysctl.conf
	sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_timestamps/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_max_orphans/d' /etc/sysctl.conf
	sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf

	echo "net.ipv4.tcp_retries2 = 8
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
	# forward ipv4
	#net.ipv4.ip_forward = 1" >>/etc/sysctl.conf
	sysctl -p
	echo "*               soft    nofile           1000000
	*               hard    nofile          1000000" >/etc/security/limits.conf
	echo "ulimit -SHn 1000000" >>/etc/profile
	read -p "需要重启VPS，系统优化配置才能生效，是否现在重启？ [Y/n] :" yn
	[[ -z $yn ]] && yn="y"
	if [[ $yn == [Yy] ]]; then
		yellow "VPS 重启中..."
		reboot
	fi
}

open_ports() {
	systemctl stop firewalld.service
	systemctl disable firewalld.service
	setenforce 0
	ufw disable
	iptables -P INPUT ACCEPT
	iptables -P FORWARD ACCEPT
	iptables -P OUTPUT ACCEPT
	iptables -t nat -F
	iptables -t mangle -F
	iptables -F
	iptables -X
	netfilter-persistent save
	yellow "VPS中的所有网络端口已开启"
}

#禁用IPv6
closeipv6() {
	clear
	sed -i '/net.ipv6.conf.all.disable_ipv6/d' /etc/sysctl.d/99-sysctl.conf
	sed -i '/net.ipv6.conf.default.disable_ipv6/d' /etc/sysctl.d/99-sysctl.conf
	sed -i '/net.ipv6.conf.lo.disable_ipv6/d' /etc/sysctl.d/99-sysctl.conf
	sed -i '/net.ipv6.conf.all.disable_ipv6/d' /etc/sysctl.conf
	sed -i '/net.ipv6.conf.default.disable_ipv6/d' /etc/sysctl.conf
	sed -i '/net.ipv6.conf.lo.disable_ipv6/d' /etc/sysctl.conf

	echo "net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1" >>/etc/sysctl.d/99-sysctl.conf
	sysctl --system
	green "禁用IPv6结束，可能需要重启！"
}

#开启IPv6
openipv6() {
	clear
	sed -i '/net.ipv6.conf.all.disable_ipv6/d' /etc/sysctl.d/99-sysctl.conf
	sed -i '/net.ipv6.conf.default.disable_ipv6/d' /etc/sysctl.d/99-sysctl.conf
	sed -i '/net.ipv6.conf.lo.disable_ipv6/d' /etc/sysctl.d/99-sysctl.conf
	sed -i '/net.ipv6.conf.all.disable_ipv6/d' /etc/sysctl.conf
	sed -i '/net.ipv6.conf.default.disable_ipv6/d' /etc/sysctl.conf
	sed -i '/net.ipv6.conf.lo.disable_ipv6/d' /etc/sysctl.conf

	echo "net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
net.ipv6.conf.lo.disable_ipv6 = 0" >>/etc/sysctl.d/99-sysctl.conf
	sysctl --system
	green "开启IPv6结束，可能需要重启！"
}

sshdconfig() {
     if [[ ! -f ~/.ssh/authorized_keys ]]; then
          wget -N --no-check-certificate -O ~/id_rsa.pub https://raw.githubusercontent.com/lisqq1/lisqq1/main/sshd_key
     else
          return
     fi
	mkdir .ssh && cat ~/id_rsa.pub > ~/.ssh/authorized_keys && chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys
	if [[ $SYSTEM != "CentOS" ]]; then	
		echo "PubkeyAcceptedKeyTypes=+ssh-dss" >> /etc/ssh/sshd_config
	fi
	sed -i -e "s|#Port 22|Port 8022|g" -e "s|#PasswordAuthentication yes|PasswordAuthentication no|g" -e "s|#PubkeyAuthentication yes|PubkeyAuthentication yes|g" /etc/ssh/sshd_config
	systemctl restart sshd
}

auto() {
	setdns64 && sshdconfig
     TLS="true" && WS="true" && install
	rm -rf ~/install.sh
     rm -rf ~/id_rsa.pub 
     rm -rf ~/$KEY
     rm -rf ~/$PEM
     rm -rf ~/ml.tar.gz
}

action=$1
#intt=$2
#[[ -z $2 ]] && read -p "请输入vps的序号" intt
#((intt=$action-1))
[[ -z $1 ]] && exit 
((intt=$action-1))
case "$action" in
	[0-6]) auto ;;
	update | uninstall | start | restart | stop | showLog | sshdconfig) ${action} ;;
	*) exit  ;;
esac

#case "$action" in
#	auto | update | uninstall | start | restart | stop | showLog | sshdconfig) ${action} ;;
#	*) auto ;;
#esac
