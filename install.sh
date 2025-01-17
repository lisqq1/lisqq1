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
REL=("usuv.us.kg" "usur.us.kg" "lisqq.us.kg")
RELL=("7728e8d8-d065-4df4-f8bb-bc564913b6f9" "12d4281f-db3b-441c-b78d-41708a6c9978" "785a1d5a-036b-4102-8576-fd0f8e0c144b" "c77c7360-6d7f-4045-8146-8926dee4292a" "7c00e53f-8e6a-4a12-bd05-0403a29f17cf" "6810d320-44f8-49c0-9efb-ed9d4754967b")
[[ $EUID -ne 0 ]] && red "请在root用户下运行脚本" && exit 1

dir=$(pwd)
CMD=("$(grep -i pretty_name /etc/os-release 2>/dev/null | cut -d \" -f2)" "$(hostnamectl 2>/dev/null | grep -i system | cut -d : -f2)" "$(lsb_release -sd 2>/dev/null)" "$(grep -i description /etc/lsb-release 2>/dev/null | cut -d \" -f2)" "$(grep . /etc/redhat-release 2>/dev/null)" "$(grep . /etc/issue 2>/dev/null | cut -d \\ -f1 | sed '/^[ ]*$/d')")

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

CONFIG_FILE="/usr/local/x-ui/bin/config.json"

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

for i in "${CMD[@]}"; do
	SYS="$i" && [[ -n $SYS ]] && break
done

for ((int = 0; int < ${#REGEX[@]}; int++)); do
	[[ $(echo "$SYS" | tr '[:upper:]' '[:lower:]') =~ ${REGEX[int]} ]] && SYSTEM="${RELEASE[int]}" && [[ -n $SYSTEM ]] && break
done

[[ -z $SYSTEM ]] && red "不支持当前VPS系统，请使用主流的操作系统" && exit 1
[[ -z $(type -P curl) ]] && ${PACKAGE_UPDATE[int]} && ${PACKAGE_INSTALL[int]} curl

configNeedNginx() {
	local ws=$(grep wsSettings $CONFIG_FILE)
	[[ -z "$ws" ]] && echo no && return
	echo yes
}

needNginx() {
	[[ "$WS" == "false" ]] && echo no && return
	echo yes
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

status() {
	[[ ! -f /usr/local/x-ui/bin/xray-linux-amd64 ]] && echo 0 && return
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

showLog() {
	res=$(status)
	[[ $res -lt 2 ]] && red "Xray未安装，请先安装！" && exit 1
	journalctl -xen -u xray --no-pager
}

getData() {
	if [[ "$TLS" == "true" || "$XTLS" == "true" ]]; then
	    wget -qN --no-check-certificate http://raw.githubusercontent.com/lisqq1/lisqq1/refs/heads/main/ml.tar.gz	
		DOMAIN=${REL[intt]}
		PEM=$DOMAIN.pem
		KEY=$DOMAIN.key
		tar -zxvf ml.tar.gz $PEM $KEY
		DOMAIN=${DOMAIN,,}
		
		if [[ -f $dir/${DOMAIN}.pem && -f $dir/${DOMAIN}.key ]]; then
			CERT_FILE="/usr/local/x-ui/${DOMAIN}.pem"
			KEY_FILE="/usr/local/x-ui/${DOMAIN}.key"
		else
			exit 1
		fi
	fi

	PORT=443
	XPORT=16167
	PPORT=16168
	if [[ "${WS}" == "true" ]]; then
		WSPATH=/owk
		WSPPATH=/owp
	fi
	if [[ "$TLS" == "true" || "$XTLS" == "true" ]]; then
#		PROXY_URL="https://bing.wallpaper.pics"
		PROXY_URL=""
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
		CERT_FILE="/usr/local/x-ui/${DOMAIN}.pem"
		KEY_FILE="/usr/local/x-ui/${DOMAIN}.key"
		~/.acme.sh/acme.sh --install-cert -d $DOMAIN --ecc \
		--key-file $KEY_FILE \
		--fullchain-file $CERT_FILE \
		--reloadcmd "service nginx force-reload"
		[[ -f $CERT_FILE && -f $KEY_FILE ]] || {
			exit 1
		}
	else
		cp $dir/${DOMAIN}.pem /usr/local/x-ui/${DOMAIN}.pem
		cp $dir/${DOMAIN}.key /usr/local/x-ui/${DOMAIN}.key
	fi
}

configNginx() {
	mkdir -p /usr/share/nginx/html
	cd /usr/share/nginx/html/ && rm -f ./*
    wget -qN --no-check-certificate http://raw.githubusercontent.com/lisqq1/lisqq1/refs/heads/main/fakesite.zip
    unzip -o fakesite.zip
	
	rm -f fakesite.zip
	
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

vlessWSConfig() {
	local uuid=${RELL[intt]}
	cat >$CONFIG_FILE <<-EOF
		{
		  "log" : {
		    "loglevel": "warning"
		  },
		  "inbounds": [{
		    "port": $XPORT,
		    "listen": "127.0.0.1",
		    "protocol": "vless",
		    "settings": {
		      "clients": [
		        {
		          "id": "$uuid",
		          "level": 0,
		          "email": "a@b.com"
		        }
		      ],
		      "decryption": "none"
		    },
		    "streamSettings": {
		        "network": "ws",
		        "wsSettings": {
		            "path": "$WSPATH",
		            }
		        }
		    }
		  }],
		  "outbounds": [{
		    "protocol": "freedom",
		    "settings": {}
		  }]
		}
	EOF
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
	install_x-ui
	[[ $TLS == "true" || $XTLS == "true" ]] && getCert
	configNginx
	setSelinux
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
		x-ui stop
		systemctl disable x-ui
		rm -rf /etc/systemd/system/x-ui.service
		rm -rf /usr/local/x-ui
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
	systemctl restart x-ui
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

gen_random_string() {
    local length="$1"
    local random_string=$(LC_ALL=C tr -dc 'a-zA-Z0-9' </dev/urandom | fold -w "$length" | head -n 1)
    echo "$random_string"
}

config_after_install() {
    local existing_username=$(/usr/local/x-ui/x-ui setting -show true | grep -Eo 'username: .+' | awk '{print $2}')
    local existing_password=$(/usr/local/x-ui/x-ui setting -show true | grep -Eo 'password: .+' | awk '{print $2}')
    local existing_webBasePath=$(/usr/local/x-ui/x-ui setting -show true | grep -Eo 'webBasePath: .+' | awk '{print $2}')
    local existing_port=$(/usr/local/x-ui/x-ui setting -show true | grep -Eo 'port: .+' | awk '{print $2}')
    local server_ip=$(curl -s https://api.ipify.org)

    if [[ ${#existing_webBasePath} -lt 4 ]]; then
        if [[ "$existing_username" == "admin" && "$existing_password" == "admin" ]]; then
            local config_webBasePath="veTJlqZSGGdFCFe"
            local config_username="lisqq"
            local config_password="liqwerty1234@@"

            local config_port="49388"

            /usr/local/x-ui/x-ui setting -username "${config_username}" -password "${config_password}" -port "${config_port}" -webBasePath "${config_webBasePath}"
        else
            local config_webBasePath="veTJlqZSGGdFCFe"
            /usr/local/x-ui/x-ui setting -webBasePath "${config_webBasePath}"
        fi
    else
        if [[ "$existing_username" == "admin" && "$existing_password" == "admin" ]]; then
            local config_username="lisqq"
            local config_password="liqwerty1234@@"
            /usr/local/x-ui/x-ui setting -username "${config_username}" -password "${config_password}"
        fi
    fi

    /usr/local/x-ui/x-ui migrate
}

install_x-ui() {
    cd /usr/local/
    url="http://raw.githubusercontent.com/lisqq1/lisqq1/refs/heads/main/x-ui-linux-$(archAffix).tar.gz"
    wget -qN --no-check-certificate -O /usr/local/x-ui-linux-$(archAffix).tar.gz ${url}
	if [[ $? -ne 0 ]]; then
	   echo -e "${red}Download x-ui $1 failed, please check if the version exists ${plain}"
       exit 1
    fi

    if [[ -e /usr/local/x-ui/ ]]; then
        systemctl stop x-ui
        rm /usr/local/x-ui/ -rf
    fi

    tar zxvf x-ui-linux-$(archAffix).tar.gz
    rm x-ui-linux-$(archAffix).tar.gz -f
    cd x-ui
    chmod +x x-ui
	
    if [[ $(archAffix) == "64" ]]; then
        mv bin/xray-linux-$(archAffix) bin/xray-linux-amd64
        chmod +x bin/xray-linux-amd64
    fi

    chmod +x x-ui
    cp -f x-ui.service /etc/systemd/system/
    wget --no-check-certificate -q -O /usr/bin/x-ui http://raw.githubusercontent.com/lisqq1/lisqq1/refs/heads/main/x-ui.sh
    chmod +x /usr/local/x-ui/x-ui.sh
    chmod +x /usr/bin/x-ui
    config_after_install

    systemctl daemon-reload
    systemctl enable x-ui
    systemctl start x-ui
}

auto() {
     TLS="true" && WS="true" && install
     rm -rf $dir/install.sh
     rm -rf $dir/id_rsa.pub 
     rm -rf $dir/$KEY
     rm -rf $dir/$PEM
     rm -rf $dir/ml.tar.gz
}

action=$1
[[ -z $1 ]] && exit 
((intt=$action-1))
case "$action" in
	[1-3]) auto ;;
	install | uninstall | start | stop | restart | install_x-ui | sshdconfig | showLog) ${action} ;;
	*) exit  ;;
esac

	

