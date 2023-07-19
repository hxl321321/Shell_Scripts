#!/bin/bash
# export LANG=zh_CN.UTF-8
# DESCRIPTION: Nagios Plugin for checking status of network bond DEVICEs on linux.
# AUTHOR: Xiaolong He
# DATE: 2022 06-13

#hostip=`hostname -I | awk -F " " '{print $1}'`
resultfile=/tmp/repo.repotxt
# 检查是否为root用户，脚本必须在root权限下运行
root_check(){
echo "------------------------------------------"
if [[ "$(whoami)" != "root" ]]; then
    echo "*please run this script as root !*" > /dev/null
    exit 1
fi
#echo -e "\033[31m the script only Support CentOS_7 x86_64 \033[0m"
#echo -e "\033[31m system initialization script, Please Seriously. press ctrl+C to cancel \033[0m"
echo "-------------------开始-------------------"
}




#锁定无关紧要的用户,如果要启用某用户passwd -u <username>
shoulelockunuse_check(){
echo "------------------------------------------"
declare -a alluserlist
userlist=(sync shutdown halt uucp operator games gopher)
intersections=()
i=0
for user in `awk -F':' '{ print $1}' /etc/passwd`
do
        alluserlist[$i]=$user
        i=$i+1
done
#echo "${alluserlist[*]}"
#echo "${userlist[*]}"
for j in "${alluserlist[@]}"
do
        for k in "${userlist[@]}"
        do
                if [[ "$j" == "$k" ]];then
                intersections+=( "$j" )
                fi
        done

done
for element in ${intersections[*]};do
        echo    "*用户: $element 应被锁定！*"
        #passwd -l $element > /dev/null
done
echo "      锁定无关紧要的用户检查完成！"
echo "------------------------------------------"
}
#保护重要文件，可用chattr -i <username>取消该操作
protect_files(){
    if [ ! -f "/etc/passwd_bak" ];then
        cp -p /etc/passwd /etc/passwd_bak
        echo "/etc/passwd备份完成！"
        chattr +i /etc/passwd
    else
        echo "/etc/passwd_bak备份文件已存在，未作修改！"
    fi
    if [ ! -f "/etc/shadow_bak" ];then
        cp -p /etc/shadow /etc/shadow_bak
        echo "/etc/shadow备份完成！"
        chattr +i /etc/shadow
    else
        echo "/etc/shadow_bak备份文件已存在，未作修改！"
    fi
        if [ ! -f "/etc/group_bak" ];then
        cp -p /etc/group /etc/group_bak
        echo "/etc/group备份完成！"
        chattr +i /etc/group
    else
        echo "/etc/group_bak备份文件已存在，未作修改！"
    fi
    
    if [ ! -f "/etc/gshadow_bak" ];then
        cp -p /etc/gshadow /etc/gshadow_bak
        echo "/etc/gshadow备份完成！"
        chattr +i /etc/gshadow
    else
        echo "/etc/gshadow_bak备份文件已存在，未作修改！"
    fi
echo "/etc/passwd；/etc/shadow；/etc/group；/etc/gshadow 被限制修改,设置完成！"
#特权用户(UID为0的用户)
for user in $(awk -F: '($3 == 0) { print $1 }' /etc/passwd);
do
echo "特权用户(UID为0的用户):"$user
done
}





#特权用户检查
superuser_check(){
echo "------------------------------------------"
for user in $(awk -F: '($3 == 0) { print $1 }' /etc/passwd);
do
	echo "特权用户(UID为0的用户):"$user
done
echo "            特权用户检查完成！"
echo "------------------------------------------"
}


#空密码用户检查
emptypw_check(){
echo "------------------------------------------"
emptryuser=""
emptryuser=$(awk -F':' '($2==""){print $1 }' /etc/shadow)
if [ $emptryuser ! = "" ];then
	for empuser in $emptryuser
do
	echo "*$empuser用户密码为空,请及时设置密码！*"
done					
else
	echo "无空密码用户！"
fi
echo "           空密码用户检查完成！"
echo "------------------------------------------"
}



#对root为ls、rm设置别名
alias_check(){
echo "------------------------------------------"
shell=$SHELL
case $shell in 
"/bin/bash")
    grep -q "alias ls='ls -aol'"  ~/.bashrc && echo "ls别名已存在" || echo "*ls别名不存在*"
    grep -q "alias rm='rm -i'" ~/.bashrc && echo "rm别名已存在" ||  echo "*rm别名不存在*"
;; 
"bin/csh")
    grep -q "alias ls='ls -aol'"  ~/.cshrc && echo "ls别名已存在" || echo "*ls别名不存在*"
    grep -q "alias rm='rm -i'" ~/.cshrc && echo "rm别名已存在" ||  echo "*rm别名不存在*"
;;
*)
esac
echo "           ls、rm别名检查完成！"
echo "------------------------------------------"
}


#设置ls、rm别名
alias_set(){
echo "------------------------------------------"
shell=$SHELL
case $shell in 
"/bin/bash")
if [ ! -f ~/.bashrc_bak ];then
    	cp -p  ~/.bashrc  ~/.bashrc_bak
	echo "~/.bashrc备份完成!"
else
	echo "~/.bashrc备份已存在!"
fi
grep -q "alias ls='ls -aol'"  ~/.bashrc || (echo "alias ls='ls -aol'" >> ~/.bashrc && echo "ls别名设置完成！")
grep -q "alias rm='rm -i'" ~/.bashrc || (echo "alias rm='rm -i'" >> ~/.bashrc && echo "rm别名设置完成！")
;; 
"bin/csh")
if [ ! -f ~/.csh_bak ];then
	cp -p  ~/.cshrc  ~/.cshrc_bak
	echo "~/.csh备份完成!"
else
	echo "~/.csh备份已存在!"
fi
grep -q "alias ls='ls -aol'"  ~/.cshrc || (echo "alias ls='ls -aol'" >> ~/.cshrc && echo "ls别名设置完成！")
grep -q "alias rm='rm -i'" ~/.cshrc || (echo "alias rm='rm -i'" >> ~/.cshrc && echo "rm别名设置完成！")
;;
*)
esac
echo "           ls、rm别名设置完成！"
echo "------------------------------------------"
}



#设置密码策略,使配置生效需重启服务器.帐户被锁定后，可使用faillog -u <username> -r或pam_tally --user <username> --reset解锁
passwdproxy_check(){
echo "------------------------------------------"
if [ -f /etc/login.defs ];then
grep -q "^PASS_MAX_DAYS.*60" /etc/login.defs && echo "密码60天过期已设置！" || echo "*密码60天过期未设置！*"
grep -q "^PASS_MIN_LEN.*8" /etc/login.defs && echo "密码长度8位已设置！" || echo "*密码长度8位未期未设！*"
else
	echo "/etc/login.defs文件不存在！"
fi
echo "  /etc/login.defs密码策略检查完成！"
echo "------------------------------------------"
}



#设置密码策略
passwdproxy_set(){
echo "------------------------------------------"
if [ ! -f "/etc/login.defs_bak" ];then
    cp -p /etc/login.defs /etc/login.defs_bak
    echo "/etc/login.defs备份完成！"
else
    echo "/etc/login.defs备份已存在!"
fi
sed -i 's/^PASS_MAX_DAYS.*$/PASS_MAX_DAYS  60/' /etc/login.defs &&  echo "密码60天过期已设置完成！"
sed -i 's/^PASS_MIN_LEN.*$/PASS_MIN_LEN  8/' /etc/login.defs && echo "密码长度8位设置完成！"
echo "  /etc/login.defs密码策略设置完成！"
echo "------------------------------------------"
}




#创建/etc/security/opasswd文件
opasswd_check(){
echo "------------------------------------------"
if [ -f /etc/security/opasswd ] ;then
	echo "/etc/security/opasswd已存在！"
else
        touch /etc/security/opasswd
        chown root:root /etc/security/opasswd
        chmod 600 /etc/security/opasswd
fi
   echo "/etc/security/opasswd文件检查完成！"
echo "------------------------------------------"
}
#检查密码策略
lockuserproxy_check(){
echo "------------------------------------------"
if [ -f /etc/pam.d/system-auth ];then
	grep -q 'remember=5' /etc/pam.d/system-auth  && echo "修改密码不能与前5次相同,已设置！" ||  echo "*修改密码不能与前5次相同,未设置！*" 
	grep -q 'deny=6' /etc/pam.d/system-auth && echo "输错6次密码将被锁定,已设置！" || echo "*输错6次密码将被锁定,未设置！*"
else
	echo "*/etc/pam.d/system-auth文件不存在！*"
fi
echo "  /etc/pam.d/system-auth密码策略检查完成！"
echo "------------------------------------------"
}



#修改密码策略
lockuserproxy_set(){
echo "------------------------------------------"
if [ ! -f /etc/pam.d/system-auth_bak ];then
	cp -p /etc/pam.d/system-auth /etc/pam.d/system-auth_bak
	echo "/etc/pam.d/system-auth备份完成！"
else
	echo "/etc/pam.d/system-auth备份已存在！"
fi
grep -q 'remember=5' /etc/pam.d/system-auth || (sed -i '/^password.*requisite/a password    required                                     pam_unix.so remember=5' /etc/pam.d/system-auth && echo "修改密码，不能与前5次相同设置完成！")
grep -q 'deny=6' /etc/pam.d/system-auth || (sed -i '/^auth.*required.*pam_env\.so/i auth        required                                     pam_tally2.so  deny=6 onerr=fail' /etc/pam.d/system-auth && echo "输错6次密码将被锁定（root用户除外）设置完成！")
echo "  /etc/pam.d/system-auth密码策略设置完成！"
echo "------------------------------------------"
}


#检查帐户目录中是否存在.netrc/.rhosts文件，该文件通常会被系统或进程自动加载并执行，对系统带来安全隐患
netrcandrhosts_check(){
echo "------------------------------------------"
for dir in `cut -d":" -f6  /etc/passwd | sort | uniq`
do
if [ -d $dir ];then
        if [[  `ls -a $dir | grep  .netrc` != "" ]];then
        #cp -p $dir"/.netrc" $dir"/.netrc_bak"
               # rm -rf $dir"/.netrc"
        echo $dir"/.netrc需要备份后删除源文件！*"
        fi
        if [[  `ls -a $dir | grep  .rhosts` != "" ]];then
        #cp -p $dir"/.rhosts" $dir"/.rhosts_bak"
               # rm -rf $dir"/.rhosts"
        echo $dir"/.rhosts文件需要备份后删除源文件！*"
        fi
fi
done
echo "      .netrc和.rhosts文件检查完成！"
echo "------------------------------------------"
}

netrcandrhosts_set(){
echo "------------------------------------------"
for dir in `cut -d":" -f6  /etc/passwd | sort | uniq`
do
if [ -d $dir ];then
        if [[  `ls -a $dir | grep  .netrc` != "" ]];then
        cp -p $dir"/.netrc" $dir"/.netrc_bak"
               rm -rf $dir"/.netrc"
        echo $dir"/.netrc备份完成，源文件已被删除！*"
        fi
        if [[  `ls -a $dir | grep  .rhosts` != "" ]];then
        cp -p $dir"/.rhosts" $dir"/.rhosts_bak"
               rm -rf $dir"/.rhosts"
        echo $dir"/.rhosts文件备份完成，源文件已被删除！*"
        fi
fi
done
echo "      .netrc和.rhosts备份和源文件删除完成！"
echo "------------------------------------------"
}
#日志功能设置，记录系统日志及应用日志
rsyslog_set(){
if [ ! -f /etc/rsyslog.conf ];then
    echo "/etc/rsyslog.conf文件不存在！"
        elif [ ! -f /etc/rsyslog.conf_bak ];then
                cp -p /etc/rsyslog.conf /etc/rsyslog.conf_bak
                echo "/etc/rsyslog.conf备份完成!"
	else
		echo "/etc/rsyslog.conf_bak备份文件已存在！" 
fi
if [ -f /etc/rsyslog.conf ];then
		grep -q "^cron.*$" /etc/rsyslog.conf || (echo "cron.*	/var/log/cron" >> /etc/rsyslog.conf && echo "cron日志开启完成！")
		grep -q "^authpriv.*$" /etc/rsyslog.conf || (echo "authpriv.*	/var/log/secure" >> /etc/rsyslog.conf && echo "authpriv日志开启完成！")
		grep -q "^*.* @154.121.31.59" /etc/rsyslog.conf || (echo "*.* @154.121.31.59:514" >> /etc/rsyslog.conf && echo "日志服务器配置完成！")
		grep -q "^*.err;kern.debug;daemon.notice;.*/var/adm/messages" /etc/rsyslog.conf || (echo "*.err;kern.debug;daemon.notice;        /var/adm/messages" >> /etc/rsyslog.conf && echo "本地日志配置完成！")
	fi
if [ ! -f /etc/syslog.conf ];then
    echo "/etc/syslog.conf文件不存在！"
        elif [ ! -f /etc/syslog.conf_bak ];then
                cp -p /etc/syslog.conf /etc/syslog.conf_bak
                echo "/etc/syslog.conf备份完成!"
	else
		echo "/etc/rsyslog.conf_bak备份文件已存在！" 
fi
if [  -f /etc/syslog.conf ];then
		grep -q "^cron.*$" /etc/syslog.conf || (echo "cron.*	/var/log/cron" >> /etc/syslog.conf && echo "cron日志开启完成！")
		grep -q "^authpriv.*$" /etc/syslog.conf || (echo "authpriv.*	/var/log/secure" >> /etc/syslog.conf && echo "authpriv日志开启完成！")
		grep -q "^*.* @154.121.31.59" /etc/syslog.conf || (echo "*.* @154.121.31.59:514" >> /etc/syslog.conf && echo "日志服务器配置完成！")
		grep -q "^*.err;kern.debug;daemon.notice;.*/var/adm/messages" /etc/syslog.conf || (echo "*.err;kern.debug;daemon.notice;        /var/adm/messages" >> /etc/syslog.conf && echo "本地日志配置完成！")
	fi
if [ `netstat -nultp |grep syslog |wc -l` = 0 ];then
           service rsyslog restart > /dev/null
           service syslog restart > /dev/null
	   sleep 3
	    if [ $(ps -elf |grep rsyslog |grep -v grep |wc -l) -gt 0 ];then
		    echo "rsyslog服务重启成功！"
	    else
		    echo "rsyslog服务重启失败！"
	    fi
   else
        echo "远程已配置！"
fi	

echo "           rsyslog配置完成！"
echo "------------------------------------------"
}


#rsyslog服务配置检查
rsyslog_check(){
echo "------------------------------------------"
if [  -f /etc/rsyslog.conf ];then
    grep -q "^cron.*$" /etc/rsyslog.conf  && echo "cron日志已开启！" || echo "*cron日志未开启！*"
    grep -q "^authpriv.*$" /etc/rsyslog.conf && echo "authpriv日志已开启！" || echo "*authpriv日志未开启！*"
    grep -q "^*.* @154.121.31.59" /etc/rsyslog.conf  && echo "rsyslog日志服务器已配置！" || echo "*rsyslog日志服务器未配置！*"
    grep -q "^*.err;kern.debug;daemon.notice;.*/var/adm/messages" /etc/rsyslog.conf && echo "本地日志已配置！" || echo "*本地日志未配置！*"
else
    echo "*/etc/rsyslog.conf文件不存在！*"
fi
if [  -f /etc/syslog.conf ];then
    grep -q "^cron.*$" /etc/syslog.conf  && echo "cron日志已开启！" || echo "*cron日志未开启！*"
    grep -q "^authpriv.*$" /etc/syslog.conf && echo "authpriv日志已开启！" || echo "*authpriv日志未开启！*"
    grep -q "^*.* @154.121.31.59" /etc/syslog.conf  && echo "rsyslog日志服务器已配置！" || echo "*rsyslog日志服务器未配置！*"
    grep -q "^*.err;kern.debug;daemon.notice;.*/var/adm/messages" /etc/syslog.conf && echo "本地日志已配置！" || echo "*本地日志未配置！*"
else
    echo "*/etc/syslog.conf文件不存在！*"
fi
if [ `netstat -nultp |grep syslog |wc -l` = 0 ];then
	echo "*rsyslog服务未同步！*"
else
	echo "rsyslog服务已同步！"
fi
echo "           rsyslog配置检查完成！"
echo "------------------------------------------"
}

#隐藏sshd服务登录后提示信息信息
hide_banner(){
echo "------------------------------------------"
    if [ ! -f "/etc/ssh/sshd_config_bak" ];then
    cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config_bak > /dev/null
    echo "/etc/ssh/sshd_config备份完成！"
    grep -q "^#Banner .*$" /etc/ssh/sshd_config || (sed -i 's/^Banner .*$/#Banner none/' /etc/ssh/sshd_config && echo "ssh服务Banner隐藏设置完成！sshd服务需要重启!")
    #service sshd restart 2>&1
    else
    echo "/etc/ssh/sshd_config_bak备份文件已存在，未做任何修改！"
    fi
echo "          banner信息检查完成！"
echo "------------------------------------------"
}
#设置禁ping,禁止路由转发，修改消息队列大小
icmp_ignore(){
    if [ ! -f "/etc/sysctl.conf_bak" ];then
    cp -p /etc/sysctl.conf /etc/sysctl.conf_bak
    echo "/etc/sysctl.conf备份完成！"
    icmp=`/sbin/sysctl -n net.ipv4.icmp_echo_ignore_all`
    route=`/sbin/sysctl -n net.ipv4.conf.all.accept_source_route`
    backlog=`/sbin/sysctl -n net.ipv4.tcp_max_syn_backlog`
        if [ $icmp != 1 ];then
        /sbin/sysctl -w net.ipv4.icmp_echo_ignore_all=1 2>&1
        echo "禁ping临时生效设置完成！"
        else
        echo "禁ping临时生效设置完成！"
        fi
        if [ $route != 0 ];then
        /sbin/sysctl -w net.ipv4.conf.all.accept_source_route=0 2>&1
        echo "禁路由转发临时生效设置完成！"
        else
        echo "禁路由转发临时生效设置完成！"
        fi
        if [ $backlog != 2048 ];then
        /sbin/sysctl -w net.ipv4.tcp_max_syn_backlog=2048 2>&1
        echo "未连接队列临时修改完成！"
        else
        echo "未连接队列临时修改完成！"
        fi
    grep -q "^net.ipv4.icmp_echo_ignore_all.*=.*1" /etc/sysctl.conf
        if [ $(echo $?) != 0 ];then
        grep -q "^net.ipv4.icmp_echo_ignore_all.*$" /etc/sysctl.conf || echo "net.ipv4.icmp_echo_ignore_all = 1" >> /etc/sysctl.conf  && sed -i 's/^net.ipv4.icmp_echo_ignore_all.*$/net.ipv4.icmp_echo_ignore_all = 1/' /etc/sysctl.conf && /sbin/sysctl -p > /dev/null
        echo "禁ping永久生效设置完成！"
        else
        echo "禁ping永久生效设置完成！"
        fi
    grep -q "^net.ipv4.conf.all.accept_source_route.*=.*0" /etc/sysctl.conf
        if [ $(echo $?) != 0 ];then
        grep -q "^net.ipv4.conf.all.accept_source_route.*$" /etc/sysctl.conf || echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf  && sed -i 's/^net.ipv4.conf.all.accept_source_route.*$/net.ipv4.conf.all.accept_source_route = 0/' /etc/sysctl.conf && /sbin/sysctl -p > /dev/null
        echo "路由转发永久生效设置完成！"
        else
        echo "路由转发永久生效设置完成！"
        fi
    grep -q "^net.ipv4.tcp_max_syn_backlog.*=.*2048" /etc/sysctl.conf
        if [ $(echo $?) != 0 ];then
        grep -q "^net.ipv4.tcp_max_syn_backlog.*$" /etc/sysctl.conf || echo "net.ipv4.tcp_max_syn_backlog = 2048" >> /etc/sysctl.conf  && sed -i 's/^net.ipv4.tcp_max_syn_backlog.*$/net.ipv4.tcp_max_syn_backlog = 2048/' /etc/sysctl.conf && /sbin/sysctl -p > /dev/null
        echo "连接队列永久修改完成！"
        else
        echo "连接队列永久修改完成！"
        fi
    else
    echo "/etc/sysctl.conf_bak备份文件已存在，未做任何修改！"
    fi
}



#检查icmp
icmp_check(){
echo "------------------------------------------"
icmp=`/sbin/sysctl -n net.ipv4.icmp_echo_ignore_all`
if [ $icmp = 0  ];then
     echo "*临时禁ping未设置！*"
else
     echo "已设置临时禁ping！"
fi
grep -q "^net.ipv4.icmp_echo_ignore_all.*=.*1" /etc/sysctl.conf && echo "已设置永久禁ping！" || echo "*永久禁ping未设置！*"
echo "              icmp检查完成！"
echo "------------------------------------------"
}



#配置icmp
icmp_set(){
echo "------------------------------------------"
 if [ ! -f "/etc/sysctl.conf_bak" ];then
	 cp -p /etc/sysctl.conf /etc/sysctl.conf_bak
	 echo "/etc/sysctl.conf备份完成！"
 else
	 echo "/etc/sysctl.conf已存在备份！"
 fi
 icmp=`/sbin/sysctl -n net.ipv4.icmp_echo_ignore_all`
if [ $icmp != 1 ];then
	/sbin/sysctl -w net.ipv4.icmp_echo_ignore_all=1 2>&1
	echo "禁ping临时生效设置完成！"
else
	echo "禁ping临时生效设置完成！"
fi
grep -q "^net.ipv4.icmp_echo_ignore_all.*=.*1" /etc/sysctl.conf || (echo "net.ipv4.icmp_echo_ignore_all = 1" >> /etc/sysctl.conf && echo "永久禁ping已配置" )
echo "              icmp配置完成！"
echo "------------------------------------------"
}


#检查route转发
route_check(){
echo "------------------------------------------"
route=`/sbin/sysctl -n net.ipv4.conf.all.accept_source_route`
if [ $route != 0  ];then
     echo "*临时禁路由转发未设置！*"
else
     echo "已设置临时路由转发！"
fi
grep -q "^net.ipv4.conf.all.accept_source_route.*=.*0" /etc/sysctl.conf &&  echo "已设置永久路由转发！" || echo "*永久禁路由转发未设置！*"
echo "          route禁止转发检查完成！"
echo "------------------------------------------"
}

#设置禁止route转发
route_set(){
echo "------------------------------------------"
if [ ! -f "/etc/sysctl.conf_bak" ];then
	cp -p /etc/sysctl.conf /etc/sysctl.conf_bak
	echo "/etc/sysctl.conf备份完成！"
else
	echo "/etc/sysctl.conf已存在备份！"
fi
route=`/sbin/sysctl -n net.ipv4.conf.all.accept_source_route`
if [ $route != 0  ];then
	/sbin/sysctl -w net.ipv4.conf.all.accept_source_route=0 2>&1
	echo "route禁止转发临时生效设置完成！"
else
	echo "route禁止转发临时生效设置完成！"
fi
grep -q "^net.ipv4.conf.all.accept_source_route.*=.*0" /etc/sysctl.conf || (echo "net.ipv4.conf.all.accept_source_route = 0"  >> /etc/sysctl.conf && echo "永久禁止route转发已配置！")
echo "          route禁止转发配置完成！"
echo "------------------------------------------"
}

#检查syn攻击
syn_check(){
echo "------------------------------------------"
backlog=`/sbin/sysctl -n net.ipv4.tcp_max_syn_backlog`
if [ $backlog = 2048 ];then
     echo "已设置临时连接队列大小！"
else
     echo "*临时连接队列大小未设置！*"
fi
grep -q "^net.ipv4.tcp_max_syn_backlog.*$" /etc/sysctl.conf &&  echo "已设置永久连接队列大小！" || echo "*永久连接队列大小未设置！*"
echo "              syn检查完成！"
echo "------------------------------------------"
}

#配置syn攻击
syn_set(){
echo "------------------------------------------"
if [ ! -f "/etc/sysctl.conf_bak" ];then
	cp -p /etc/sysctl.conf /etc/sysctl.conf_bak
	echo "/etc/sysctl.conf备份完成！"
else
        echo "/etc/sysctl.conf已存在备份！"
fi      
backlog=`/sbin/sysctl -n net.ipv4.tcp_max_syn_backlog`
if [ $backlog != 2048 ];then
	/sbin/sysctl -w net.ipv4.tcp_max_syn_backlog=2048 2>&1
	echo "连接队列大小临时生效设置完成！"
else
        echo "连接队列大小临时生效设置完成！"
fi
grep -q "^net.ipv4.tcp_max_syn_backlog.*=.*2048" /etc/sysctl.conf || (echo "net.ipv4.tcp_max_syn_backlog = 2048"  >> /etc/sysctl.conf && echo "永久连接队列大小已配置！")
echo "          syn配置完成！"
echo "------------------------------------------"
}


#字符交互界面帐户超时自动退出配置
tmout_set(){
echo "------------------------------------------"
if [ ! -f /etc/csh.cshrc_bak ];then
    cp -p /etc/csh.cshrc /etc/csh.cshrc_bak
    echo "csh.cshrc备份完成！"
else
    echo "csh.cshrc_bak备份文件已存在！"
fi
    grep -q '^set.*autologout.*=.*30' /etc/csh.cshrc  || (echo "set autologout = 30" >> /etc/csh.cshrc && echo "30秒自动登出配置完成！")
if [ ! -f /etc/profile_bak ];then
    cp -p /etc/profile /etc/profile_bak
    echo "/etc/profile备份完成！"
else
    echo "/etc/profile_bak备份文件已存在！"
fi
    sed -i 's/^TMOUT.*=.*180.*$//' /etc/profile
    sed -i 's/^export.*TMOUT.*$//' /etc/profile
    grep -q '^TMOUT.*=.*180' /etc/profile || (echo  "TMOUT=180" >> /etc/profile && echo "TMOUT=180配置完成！")
    grep -q '^export.*TMOUT' /etc/profile || (echo  "export TMOUT" >> /etc/profile && echo "export TMOUT配置完成！")

echo "  字符交互界面帐户超时自动退出配置完成！"
echo "------------------------------------------"
}


#字符交互界面帐户超时自动退出检查
tmout_check(){
echo "------------------------------------------"
if [ -f /etc/csh.cshrc ];then
    grep -q '^set.*autologout.*=.*30' /etc/csh.cshrc && echo "已设置帐户超时30秒！" || echo "*未设置帐户超时30秒！*"
else
    echo “/etc/csh.cshrc文件不存在！”
fi


if [ -f /etc/profile ];then
    grep -q '^TMOUT.*=.*180' /etc/profile && echo "已设置TMOUT=180秒！" || echo "*未设置TMOUT=180秒！*"
else
    echo “/etc/profile文件不存在！”

fi
echo "  字符交互界面帐户超时自动退出检查完成！"
echo "------------------------------------------"
}
#时间同步服务检查
timesyn_check(){
echo "------------------------------------------"
if [ -f /etc/chrony.conf ] || [ -f /etc/ntp.conf ];then
	if [ -f /etc/chrony.conf ];then
	grep -q '^server.*154.121.31.10' /etc/chrony.conf && echo "chroyd已配置！" || echo "*chrony未配置！*"
	if [ `netstat -nultp |grep chronyd|wc -l` != 0 ];then
		echo "chronyd服务已启动！"
		else
		echo "*chronyd服务未启动！*"
	fi
	fi
	if [ -f /etc/ntp.conf ];then
	grep -q '^server.*154.121.31.10' /etc/ntp.conf && echo "ntpd已配置！" || echo "*ntpd未配置！*"
	if [ `netstat -nultp |grep ntpd|wc -l` != 0 ];then
		echo "ntpd服务已启动！"
	else
		echo "*ntpd服务未启动！*"
	fi
fi
else
	echo "*时间服务器未配置！*"
fi

echo "        时间同步服务检查完成！"
echo "------------------------------------------"
}
#时间同步配置
timesyn_set(){
echo "------------------------------------------"
if [ `netstat -nultp |grep chronyd|wc -l` != 0 ];then
grep -q '^server.*154.121.31.10' /etc/chrony.conf || (sed -i '/^# Please consider .*$/a server 154.121.31.10 iburst' /etc/chrony.conf && echo "chrony添加server154.121.31.10配置完成！")
else
	echo "*chronyd服务未启动！*"
fi


if [ `netstat -nultp |grep ntp|wc -l` != 0 ];then
grep -q '^server.*154.121.31.10' /etc/ntp.conf || (sed -i '/^# Please consider joining the pool/a server 154.121.31.10 iburst' /etc/ntp.conf && echo "ntp添加server154.121.31.10配置完成！")
else
	echo "*ntp服务未启动！*"
fi
echo "        时间同步服务配置完成！"
echo "------------------------------------------"
}

#Cmnd_Alias DENYCMND=!/usr/bin/passwd,!/usr/sbin/useradd,!/usr/bin/su - root,!/usr/bin/su -,!/usr/bin/rm -fr *

#rfyh ALL=(ALL)  NOPASSWD:ALL, DENYCMND
MOUNT=$(mount|egrep -iw "ext4|ext3|xfs|gfs|gfs2|btrfs"|grep -v "loop"|sort -u -t' ' -k1,2)
FS_USAGE=$(df -PThl -x tmpfs -x iso9660 -x devtmpfs -x squashfs|awk '!seen[$1]++'|sort -k6n|tail -n +2)
IUSAGE=$(df -iPThl -x tmpfs -x iso9660 -x devtmpfs -x squashfs|awk '!seen[$1]++'|sort -k6n|tail -n +2)

#只读文件检查
readly_check(){
echo "$MOUNT"|grep -w ro && echo -e "\n.....存在只读文件"|| echo -e ".....未发现只读文件"
}
#文件系统使用检查
fileusage_check(){
COL1=$(echo "$FS_USAGE"|awk '{print $1 " "$7}')
COL2=$(echo "$FS_USAGE"|awk '{print $6}'|sed -e 's/%//g')
for i in $(echo "$COL2"); do
{
  if [ $i -ge 95 ]; then
    COL3="$(echo -e $i"% 危险\n$COL3")"
  elif [[ $i -ge 85 && $i -lt 95 ]]; then
    COL3="$(echo -e $i"% 警告\n$COL3")"
  else
    COL3="$(echo -e $i"% 正常\n$COL3")"
  fi
}
done
COL3=$(echo "$COL3"|sort -k1n)
paste  <(echo "$COL1") <(echo "$COL3") -d' '|column -t
}
#挂载点检查
mountpoint_check(){
echo "$MOUNT"|column -t
}

#Inode使用检查
inode_check(){
COL11=$(echo "$IUSAGE"|awk '{print $1" "$7}')
COL22=$(echo "$IUSAGE"|awk '{print $6}'|sed -e 's/%//g')

for i in $(echo "$COL22"); do
{
  if [[ $i = *[[:digit:]]* ]]; then
  {
  if [ $i -ge 95 ]; then
    COL33="$(echo -e $i"% 危险\n$COL33")"
  elif [[ $i -ge 85 && $i -lt 95 ]]; then
    COL33="$(echo -e $i"% 警告\n$COL33")"
  else
    COL33="$(echo -e $i"% 正常\n$COL33")"
  fi
  }
  else
    COL33="$(echo -e $i"% (Inode Percentage details not available)\n$COL33")"
  fi
}
done

COL33=$(echo "$COL33"|sort -k1n)
paste  <(echo "$COL11") <(echo "$COL33") -d' '|column -t
}
#SWAP空间使用情况检查
swap_check(){
    echo -e "Total Swap Memory in MiB : "$(grep -w SwapTotal /proc/meminfo|awk '{print $2/1024}')", in GiB : "\
$(grep -w SwapTotal /proc/meminfo|awk '{print $2/1024/1024}')
    echo -e "Swap Free Memory in MiB : "$(grep -w SwapFree /proc/meminfo|awk '{print $2/1024}')", in GiB : "\
$(grep -w SwapFree /proc/meminfo|awk '{print $2/1024/1024}')
}
#当前CPU利用率检查
proc_current_check(){
    mpstat|tail -2
}
#当前CPU平均负载检查
proc_load_check(){
    echo -e "$(uptime|grep -o "load average.*"|awk '{print $3" " $4" " $5}')"
}
#僵尸进程检查
zombie_proc_check(){
ps -eo stat|grep -w Z 1>&2 > /dev/null
if [ $? == 0 ]; then
  echo -e "当前系统僵尸进程数量:" $(ps -eo stat|grep -w Z|wc -l)
  ZPROC=$(ps -eo stat,pid|grep -w Z|awk '{print $2}')
  for i in $(echo "$ZPROC"); do
      ps -o pid,ppid,user,stat,args -p $i
  done
else
 echo -e "未发现僵尸进程"
fi
}
#CPU占用前5的进程检查
cpu_top5(){
    ps -eo pcpu,pid,ppid,user,stat,args --sort=-pcpu|grep -v $$|head -6|sed 's/$/\n/'
}
#mem占用前5的进程检查
mem_top5(){
    ps -eo pmem,pid,ppid,user,stat,args --sort=-pmem|grep -v $$|head -6|sed 's/$/\n/'
}
#最近3次重启记录检查
rec_reboot(){
    last -x 2> /dev/null|grep reboot 1> /dev/null && /usr/bin/last -x 2> /dev/null|grep reboot|head -3 || echo -e "未发现重启记录"
}
#最近3次关机记录检查
rec_shutdown3(){
    ast -x 2> /dev/null|grep shutdown 1> /dev/null && /usr/bin/last -x 2> /dev/null|grep shutdown|head -3 || echo -e "未发现关机记录"
}

main(){
root_check
echo ""
echo ""
echo ""
shoulelockunuse_check
echo ""
echo ""
echo ""
emptypw_check
echo ""
echo ""
echo ""
#protect_files
echo ""
echo ""
echo ""
superuser_check
echo ""
echo ""
echo ""
alias_check
echo ""
echo ""
echo ""
alias_set
echo ""
echo ""
echo ""
opasswd_check
echo ""
echo ""
echo ""
passwdproxy_check
echo ""
echo ""
echo ""
passwdproxy_set
echo ""
echo ""
echo ""
lockuserproxy_check
echo ""
echo ""
echo ""
lockuserproxy_set
echo ""
echo ""
echo ""
netrcandrhosts_check
echo ""
echo ""
echo ""
netrcandrhosts_set
echo ""
echo ""
echo ""
rsyslog_check
echo ""
echo ""
echo ""
rsyslog_set
echo ""
echo ""
echo ""
hide_banner
echo ""
echo ""
echo ""
icmp_check
echo ""
echo ""
echo ""
#icmp_set
route_check
echo ""
echo ""
echo ""
route_set
echo ""
echo ""
echo ""
syn_check
echo ""
echo ""
echo ""
syn_set
echo ""
echo ""
echo ""
tmout_check
echo ""
echo ""
echo ""
tmout_set
echo ""
echo ""
echo ""
timesyn_check
echo ""
echo ""
echo ""
timesyn_set
echo "-------------------结束-------------------"
}
main > $resultfile

