#!/bin/sh

change_dns() {
if [ "$(nvram get adg_redirect)" = 1 ]; then
sed -i '/no-resolv/d' /etc/storage/dnsmasq/dnsmasq.conf
sed -i '/server=127.0.0.1/d' /etc/storage/dnsmasq/dnsmasq.conf
cat >> /etc/storage/dnsmasq/dnsmasq.conf << EOF
no-resolv
server=127.0.0.1#5335
EOF
/sbin/restart_dhcpd
logger -t "AdGuardHome" "添加DNS转发到5335端口"
fi
}
del_dns() {
sed -i '/no-resolv/d' /etc/storage/dnsmasq/dnsmasq.conf
sed -i '/server=127.0.0.1#5335/d' /etc/storage/dnsmasq/dnsmasq.conf
/sbin/restart_dhcpd
}

set_iptable()
{
    if [ "$(nvram get adg_redirect)" = 2 ]; then
	IPS="`ifconfig | grep "inet addr" | grep -v ":127" | grep "Bcast" | awk '{print $2}' | awk -F : '{print $2}'`"
	for IP in $IPS
	do
		iptables -t nat -A PREROUTING -p tcp -d $IP --dport 53 -j REDIRECT --to-ports 5335 >/dev/null 2>&1
		iptables -t nat -A PREROUTING -p udp -d $IP --dport 53 -j REDIRECT --to-ports 5335>/dev/null 2>&1
	done

	IPS="`ifconfig | grep "inet6 addr" | grep -v " fe80::" | grep -v " ::1" | grep "Global" | awk '{print $3}'`"
	for IP in $IPS
	do
		ip6tables -t nat -A PREROUTING -p tcp -d $IP --dport 53 -j REDIRECT --to-ports 5335 >/dev/null 2>&1
		ip6tables -t nat -A PREROUTING -p udp -d $IP --dport 53 -j REDIRECT --to-ports 5335 >/dev/null 2>&1
	done
    logger -t "AdGuardHome" "重定向53端口"
    fi
}

clear_iptable()
{
	OLD_PORT="5335"
	IPS="`ifconfig | grep "inet addr" | grep -v ":127" | grep "Bcast" | awk '{print $2}' | awk -F : '{print $2}'`"
	for IP in $IPS
	do
		iptables -t nat -D PREROUTING -p udp -d $IP --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
		iptables -t nat -D PREROUTING -p tcp -d $IP --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
	done

	IPS="`ifconfig | grep "inet6 addr" | grep -v " fe80::" | grep -v " ::1" | grep "Global" | awk '{print $3}'`"
	for IP in $IPS
	do
		ip6tables -t nat -D PREROUTING -p udp -d $IP --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
		ip6tables -t nat -D PREROUTING -p tcp -d $IP --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
	done
	
}

getconfig(){
adg_file="/etc/storage/adg.sh"
if [ ! -f "$adg_file" ] || [ ! -s "$adg_file" ] ; then
	cat > "$adg_file" <<-\EEE
bind_host: 0.0.0.0
bind_port: 3030
auth_name: admin
auth_pass: admin
language: zh-cn
rlimit_nofile: 0
dns:
  bind_host: 0.0.0.0
  port: 5335
  protection_enabled: true
  filtering_enabled: true
  blocking_mode: nxdomain
  blocked_response_ttl: 10
  querylog_enabled: true
  ratelimit: 20
  ratelimit_whitelist: []
  refuse_any: true
  bootstrap_dns:
  - 223.5.5.5
  - 223.6.6.6
  - 114.114.114.114
  - 1.1.1.1
  - 8.8.4.4
  - 8.8.8.8
  - 169.239.202.202
  all_servers: true
  allowed_clients: []
  disallowed_clients: []
  blocked_hosts: []
  parental_sensitivity: 0
  parental_enabled: false
  safesearch_enabled: false
  safebrowsing_enabled: false
  resolveraddress: ""
  upstream_dns:
  - 223.5.5.5
  - 223.6.6.6
  - 114.114.114.114
  - 1.1.1.1
  - 8.8.4.4
  - 8.8.8.8
  - 169.239.202.202
tls:
  enabled: false
  server_name: ""
  force_https: false
  port_https: 443
  port_dns_over_tls: 853
  certificate_chain: ""
  private_key: ""
filters:
- enabled: true
  url: https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
  name: AdGuard Simplified Domain Names filter
  id: 1
- enabled: true
  url: https://adaway.org/hosts.txt
  name: AdAway
  id: 2
- enabled: true
  url: https://hosts-file.net/ad_servers.txt
  name: hpHosts - Ad and Tracking servers only
  id: 3
- enabled: true
  url: https://www.malwaredomainlist.com/hostslist/hosts.txt
  name: MalwareDomainList.com Hosts List
  id: 4
user_rules: []
dhcp:
  enabled: false
  interface_name: ""
  gateway_ip: ""
  subnet_mask: ""
  range_start: ""
  range_end: ""
  lease_duration: 86400
  icmp_timeout_msec: 1000
clients: []
log_file: ""
verbose: false
schema_version: 3

EEE
	chmod 755 "$adg_file"
fi
}

dl_adg(){
logger -t "AdGuardHome" "下载AdGuardHome"
flag=1
for i in $(seq 1 3)  
do   
wget --no-check-certificate -O /tmp/AdGuardHome.tar.gz https://static.adguard.com/adguardhome/release/AdGuardHome_linux_mipsle.tar.gz
#curl -k -s -o /tmp/AdGuardHome/AdGuardHome --connect-timeout 10 --retry 3 https://cdn.jsdelivr.net/gh/chongshengB/rt-n56u/trunk/user/adguardhome/AdGuardHome
flag=$?
if [ $flag != "0" ] && [ ! -f "/tmp/AdGuardHome.tar.gz" ]; then
logger -t "AdGuardHome" "AdGuardHome下载失败，请检查是否能正常访问网络!程序将再次尝试下载..."
else
break
fi
done 

if [ $flag != "0" ] && [ ! -f "/tmp/AdGuardHome.tar.gz" ]; then
logger -t "AdGuardHome" "AdGuardHome下载失败，请检查是否能正常访问网络!程序将退出。"
nvram set adg_enable=0
exit 0
else
logger -t "AdGuardHome" "AdGuardHome下载成功。"
tar -xzf /tmp/AdGuardHome.tar.gz -C /tmp
rm -f /tmp/AdGuardHome.tar.gz /tmp/AdGuardHome/LICENSE.txt /tmp/AdGuardHome/README.md
chmod 777 /tmp/AdGuardHome/AdGuardHome
fi
}

start_adg(){
	mkdir -p /etc/storage/AdGuardHome
	if [ ! -f "/tmp/AdGuardHome/AdGuardHome" ]; then
	dl_adg
	fi
	getconfig
	change_dns
	set_iptable
	logger -t "AdGuardHome" "运行AdGuardHome"
	eval "/tmp/AdGuardHome/AdGuardHome -c $adg_file -w /etc/storage/AdGuardHome" &
        sleep 3
	if [ ! -z "$(ps -w | grep "AdGuardHome" | grep -v grep )" ]; then
	   logger -t "AdGuardHome" "启动成功"
	   /usr/bin/adguardhome.sh keep &
	else
	   logger -t "AdGuardHome" "启动失败, 注意检AdGuardHome是否下载完整,6秒后尝试重新启动..."
	   sleep 6
	   logger -t "AdGuardHome" "正在清理AdGuardHome目录..."
	   killall -9 AdGuardHome
	   del_dns
           clear_iptable
	   rm -fr /tmp/AdGuardHome/
	   start_adg
	fi
}

stop_adg(){
rm -f /tmp/AdGuardHome.tar.gz
killall -9 AdGuardHome
del_dns
clear_iptable
killall -9 adguardhome.sh
}

keep_adg(){
while true;do
  if [ $(nvram get adg_enable) = 1 ];then
  wget -O /dev/null 127.0.0.1:3030
  if [ "$?" != "0" ];then
    logger -t "AdGuardHome" "正在重启AdGuardHome..."
    start_adg
  fi
 else
  break
 fi
 sleep 60
done
}

case $1 in
start)
	start_adg
	;;
stop)
	stop_adg
	;;
keep)
	keep_adg
	;;
*)
	echo "check"
	;;
esac
