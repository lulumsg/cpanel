#!/bin/sh
# Audit Aliases
# Luciana Silva
# lu.maria06@gmail.com
# Last Update: Jul 27 2022

# Função principal, listar todas as funções disponíveis
function audit() {
echo -e "\n Lista de Funcoes\n=======================================\n"
echo -e "scan\t\t\t->\tBusca malwares usando ClamAV"
echo -e "c\t\t\t->\tRemove permissoes de script(s)"
echo -e "ftpcheck\t\t->\tMostra logs do pure-FTPd para uma conta" 
echo -e "cpanel\t\t\t->\tMostra logs de cPanel/WHM de um usuario"
echo -e "fm\t\t\t->\tLista arquivos modificados"
echo -e "csfc\t\t\t->\tVerifica conf do CSF"
echo -e "topusr\t\t\t->\tMonitorar processos de um usuario"
echo -e "listacon\t\t->\tLista conexao em portas"
echo -e "apachecons\t\t->\tListar conexoes ao Apache"
echo -e "listamysql\t\t->\tListar conexoes ao MySQL"
echo -e "dovecotcheck\t\t->\tConexoes ao Dovecot"
echo -e "dvimapcheck\t\t->\tConexoes Dovecot/IMAP"
echo -e "checkdisks\t\t->\tChecar discos"
echo -e "mq\t\t\t->\tDetalhar Mail Queue"
echo -e "dvpopcheck\t\t->\tConexoes Dovecot/POP"
echo -e "inodescnt\t\t->\tContar inodes de uma conta"
echo -e "listdisk\t\t->\tListar uso de espaco em disco das contas"
echo -e "dcp\t\t\t->\tLista utilização de Memoria, CPU, MYSQL das contas"
echo -e "top_sendmail_users\t->\tidentificar usuários abusando do sendmail"
echo -e "top_smtpdovecot_users\t->\tidentificar usuários abusando do dovecot"
echo -e "dcpu\t\t\t->\tLista utilização de Memoria, CPU, MYSQL de uma conta"
echo -e "trafegohttp\t\t->\tCheca a quantidade de hits de uma conta"
echo -e "apache_status\t\t->\tFullstatus do Apache"
echo -e "edit_http\t\t->\tAbre o arquivo pre_virtualhost_global.conf para edição"
echo -e "restrict_http\t\t->\tBloqueia o acesso web da conta cPanel"
echo -e "mailogin_history\t->\tRelatório de login das contas de e-mail de um domínio"
echo -e "mail_usage_report\t->\tRelatório de todas as contas de e-mail do servidor"
echo -e "cpusermail_usage\t->\tRelatório das contas de e-mail de uma conta cPanel"
echo -e "changemail_password\t->\tAlterar senha de conta para uma aleatória"
echo -e "nomail\t\t\t->\tDesabilitar envio de e-mail de uma conta cPanel"
echo -e "yesmail\t\t\t->\tHabilitar envio de e-mail de uma conta cPanel"
echo -e "delfrozen\t\t->\tRemover e-mails frozen da fila"
echo -e "deldonmail\t\t->\tRemover e-mails de todo domínio da fila"
echo -e "delusermail\t\t->\tRemover e-mails de uma conta da fila"
echo -e "sendmail\t\t->\tEnviar e-mail"
echo -e "checkmx\t\t\t->\tVerifica roteamento de e-mail e entradas MX do domínio"
echo -e "autossl\t\t\t->\tGerar certificado ssl para conta"
echo -e "restrict_mailacct\t->\tDesabilitar conta de e-mail Login/Envio/Recebimento"
echo -e "unrestrict_mailacct\t->\tRemover bloqueio de conta de e-mail Login/Envio/Recebimento"
echo -e "phpinfo\t\t\t->\tAdiciona o phpinfo no diretório atual"
echo -e "enableshell\t\t\t->\tLibera acesso ssh ao usuário"
echo -e "\nEnviar sugestoes para lu.maria06@gmail.com\n" ;}


# Listando todas as funções disponíveis quando carregar o aliases
audit;

# Aliases principais
alias ls="ls -al --color=always";export LESS="r";
alias ud="cat /etc/userdomains | grep --color=auto";
alias dus="cat /etc/domainusers | grep --color=auto";
alias tus="cat /etc/trueuserowners | grep --color=auto";
alias c="chmod 000"; 

function domain_verify(){
verifydomain=$(grep -w $domain /etc/trueuserdomains | cut -d: -f1 | head -1)

if [ "$verifydomain" != "$domain" ]; then
  echo -e "The domain \033[1;33m$domain\033[0m does not exist: \033[0;31m[ERROR]\033[0m"
  kill -INT $$;
fi;
}

function mail_verify(){
mailuser=$(echo $user | cut -d@ -f1 | head -1)

if [[ ! -d "/home/$account/mail/$domain/$mailuser" ]]; then
  echo -e "The mail account \033[1;33m$user\033[0m does not exist: \033[0;31m[ERROR]\033[0m"
  kill -INT $$;
fi;
}

function acct_verify(){
verifyuser=$(grep -w $user /etc/trueuserdomains | cut -d: -f2 | head -1 | sed 's/ //g' )

if [ "$verifyuser" != "$user" ]; then
  echo -e "The user \033[1;33m$user\033[0m does not exist: \033[0;31m[ERROR]\033[0m"
  kill -INT $$;
fi;
}

# Funções
function scan() { clamdscan --stdout | grep FOUND | cut -d: -f1 | xargs ls -l ;}

function mq() { exim -bp | grep "<*>" | awk {'print $4'} | sort | uniq -c | sort -n ;}

function ftpcheck() { grep $1 /var/log/messages | grep ftp; }

function cpanel() { grep "\- $1" /usr/local/cpanel/logs/access_log | grep --color=auto -E '"(POST|GET) .*(post_login|xfercpanel|live_statfiles|live_fileop|passwd|doupload-ajax|editit|doadddomain|wwwacct|editcron|upload.html|trashit.html|domkdir.html|/scripts/(edit|add)pkg\?|/scripts2/dochangeemail|/scripts2/multikilllist|/scripts6/edit_contact_info|xml-api/createacct|changesiteip|chrootpass|/xml-api/nvset|apachesetup|ftpconfiguration|tweakftp|bandminpass|reservedip|eximconf|(add|del)(user|db|pop|fwd)(confirm|todb)?|/cgi/addon_csf.cgi|logout|domkfile|saveedituser|domassmodify|savefile).* HTTP/[[:digit:].]+"'; }

function fm() { find -mtime -$1 -ls; }

function csfc() { egrep "(SMTP_BLOCK|SMTP_ALLOWLOCAL|SMTP_PORTS)[[:space:]]?=" /etc/csf/csf.conf; csf -v; }

function listacon() { netstat -plan | grep ":$1 " | awk {'print $5'} |sed 's/::ffff://g' | cut -d: -f1 | sort | uniq -c | sort -nr | head; }

function inodescnt() { echo -e "Total:"; find /home/$1 -type f | wc -l; echo -e "\n"; cd /home/$1 ; echo -e "Por Diretorios:\n"; for a in `find . -maxdepth 1 -type d | grep "./"`; do echo -ne "$a: "; find `pwd`/$a -type f | wc -l; done }

function topusr() { top -c -d1 | grep $1; }


function checkdisks() { for i in {0..3}; do printf p$i:; echo; smartctl -ad 3ware,$i /dev/twa0 | grep -i reallocated_sector; smartctl -ad 3ware,$i /dev/twa0 | grep -i current_pending; smartctl -ad 3ware,$i /dev/twa0 | grep -i offline_uncorr; smartctl -ad 3ware,$i /dev/twa0 | grep -i 'ATA Error'; echo; done; printf sdb:; echo; smartctl -a /dev/sdb | grep -i reallocated_sector; smartctl -a /dev/sdb | grep -i current_pending; smartctl -a /dev/sdb | grep -i offline_uncorrect; smartctl -a /dev/sdb | grep -i 'ATA Error';  }

function listdisk()  { du -h /home/ --max-depth=1 | grep G; }

function apachecons() { service httpd fullstatus | grep -B 1 "GET" | grep -A 0 "GET" | cut -d" " -f4 | grep "^[a-z]" | sort | uniq -c | sort -rn | head ;}

function listamysql() { proc=`mysqladmin proc`; echo -e "$proc"; echo -e "$proc" | awk {'print $4'} | grep "^[a-z]\|^[A-Z]" | grep -v "User" | sort | uniq -c | sort -rn; }

function dovecotcheck() { echo -e "\nIMAP:\n"; grep Login /var/log/maillog | grep imap | cut -d "@" -f2 | cut -d ">" -f1 | grep -v dovecot | sort | uniq -c | sort -n | tail -10; echo -e "\nPOP:\n"; grep Login /var/log/maillog | grep pop | cut -d "@" -f2 | cut -d ">" -f1 | grep -v dovecot | sort | uniq -c | sort -n | tail -10; echo -e "\nIMAP Total:\n"; grep Login /var/log/maillog* | grep imap | cut -d "@" -f2 | cut -d ">" -f1 | grep -v dovecot | sort | uniq -c | sort -n | tail -10; echo -e "\nPOP Total:\n"; grep Login /var/log/maillog* | grep pop | cut -d "@" -f2 | cut -d ">" -f1 | grep -v dovecot | sort | uniq -c | sort -n | tail -10; }

function dvimapcheck() { IFS=" "; history=`grep $1 /var/log/maillog | grep Login | grep imap | cut -d "<" -f2 | cut -d ">" -f1 | sort | uniq -c | sort -n`; echo -e "Historico:\n$history\n"; }

function dvpopcheck() { IFS=" "; history=`grep $1 /var/log/maillog | grep Login | grep pop | cut -d "<" -f2 | cut -d ">" -f1 | sort | uniq -c | sort -n`; echo -e "Historico:\n$history\n"; }

function phpini() { grep "\(register_globals =\|allow_url_fopen\|memory_limit\|max_\|_time\|magic_quotes\)" /usr/lib/php.ini | grep -v "\(sql\|syb\|ifx\|odbc\|ingres\|socket\|call\)"; }

function dcp() { OUT=$(/usr/local/cpanel/bin/dcpumonview | grep -v Top | sed -e 's#<[^>]*># #g' | while read i ; do NF=`echo $i | awk {'print NF'}` ; if [[ "$NF" == "5" ]] ; then USER=`echo $i | awk {'print $1'}`; OWNER=`grep -e "^OWNER=" /var/cpanel/users/$USER | cut -d= -f2` ; echo "$OWNER $i"; fi ; done) ; (echo "USER CPU" ; echo "$OUT" | sort -nrk4 | awk '{printf "%s %s%\n",$2,$4}' | head -5) | column -t ; echo; (echo -e "USER MEMORY" ; echo "$OUT" | sort -nrk5 | awk '{printf "%s %s%\n",$2,$5}' | head -5) | column -t;  echo; (echo -e "USER MYSQL" ; echo "$OUT" | sort -nrk6 | awk '{printf "%s %s%\n",$2,$6}' | head -5) | column -t;}

function top_sendmail_users() { exigrep sendmail /var/log/exim_mainlog | grep home | cut -d "=" -f2 | cut -d " " -f1 | sort | uniq -c | sort -n | tail -15; }

function top_smtpdovecot_users() { exigrep dovecot_login /var/log/exim_mainlog | grep "<=" | awk {'print $5'} | sort | uniq -c | sort -n | tail -10; }

function dcpu() { { for i in `seq 1 7 `; do let i=$i+1 ; let  k=$i-1 ; let s="$(date +%s) - (k-1)*86400"; let t="$(date +%s) - (k-2)*86400"; echo `date -Idate -d "1970-01-01 $s sec"`; /usr/local/cpanel/bin/dcpumonview `date -d "1970-01-01 $s sec" +%s` `date -d "1970-01-01 $t sec" +%s` | sed -r -e 's@^<tr bgcolor=#[[:xdigit:]]+><td>(.*)</td><td>(.*)</td><td>(.*)</td><td>(.*)</td><td>(.*)</td></tr>$@Account: \1\tDomain: \2\tCPU: \3\tMem: \4\tMySQL: \5@' -e 's@^<tr><td>Top Process</td><td>(.*)</td><td colspan=3>(.*)</td></tr>$@\1 - \2@' |  grep "Domain: $2" -A3 ; done }; for i in `seq 1 20 `; do alias "$i"'day'='dcp '"$i" ; done ;}

function trafegohttp () {
 {
     echo -ne "Arquivo:\t/usr/local/apache/domlogs/$1\n"; echo -ne "Inicio:\t"; head -n1 "/usr/local/apache/domlogs/$1" | sed -nr "s/.*(\[[^]]*\]).*/\1/p"; echo -ne "Fim: \t"; tail -n1 "/usr/local/apache/domlogs/$1" | sed -nr "s/.*(\[[^]]*\]).*/\1/p"; echo -ne "Total Horas:\t"; TOTALHOUR=$(echo "(`tail -n1 "/usr/local/apache/domlogs/$1" | awk 'BEGIN{ m=split("Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec",d,"|"); for(o=1;o<=m;o++){ date[d[o]]=sprintf("%02d",o) } } { gsub(/\[/,"",$4); gsub(":","/",$4); gsub(/\]/,"",$5); n=split($4, DATE,"/"); day=DATE[1]; mth=DATE[2]; year=DATE[3]; hr=DATE[4]; min=DATE[5]; sec=DATE[6]; MKTIME= mktime(year" "date[mth]" "day" "hr" "min" "sec); print MKTIME }'`-`head -n1 "/usr/local/apache/domlogs/$1" | awk 'BEGIN{ m=split("Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec",d,"|"); for(o=1;o<=m;o++){ date[d[o]]=sprintf("%02d",o) } } { gsub(/\[/,"",$4); gsub(":","/",$4); gsub(/\]/,"",$5); n=split($4, DATE,"/"); day=DATE[1]; mth=DATE[2]; year=DATE[3]; hr=DATE[4]; min=DATE[5]; sec=DATE[6]; MKTIME= mktime(year" "date[mth]" "day" "hr" "min" "sec); print MKTIME }'` ) / 3600" | bc -l | xargs printf "%1.2f"); echo $TOTALHOUR; echo -n "Total Hits: "; TOTALRAW=`wc -l "/usr/local/apache/domlogs/$1" | awk '{print $1}'`; AVGPERHOUR=`echo "$TOTALRAW/$TOTALHOUR" | bc -l | xargs printf "%1.0f"`; echo "$TOTALRAW (media $AVGPERHOUR por hora)";
 }
}

function phpinfo() { usuario=$(pwd | cut -d\/ -f3);echo "<?php phpinfo(); ?>" >> phpinfo.php; chmod 644 phpinfo.php; chown $usuario: phpinfo.php;}

function maillocate_verify(){
local=$(grep -w $domain /etc/localdomains | head -1)

if [ "$local" != "$domain" ]; then
  echo -e "The domain \033[1;33m$domain\033[0m are configured as remote domain "
else
  echo -e "The domain \033[1;33m$domain\033[0m are configured as local domain "
fi;
}

function restrict_http() {
SCRIPT_PATH="/scripts/restartsrv_httpd"
NOW=$(date +"%m-%d-%y")
user=${1}
acct_verify

echo -e "<Directory \"/home/$user/public_html\">\n  AllowOverride none\n  order deny,allow\n  errordocument 403 \"Temporarily closed for maintenance.\n  #\" ~$agent on $NOW \n</Directory>\n\n" >> /usr/local/apache/conf/includes/pre_virtualhost_global.conf;

"$SCRIPT_PATH";}

function delusermail() {
emailacct=${1}
exiqgrep -i -f $emailacct | xargs exim -Mrm;
}

function deldonmail() {
domain=${1}
exim -bpu | grep $domain | awk {'print $3'} | xargs exim -Mrm;
}

function delfrozen() {
        exim -bpu | grep "<>" | awk '{print $3}' | xargs exim -Mrm;
}

function autossl(){
user=${1}
acct_verify
SCRIPT_PATH="/usr/local/cpanel/bin/autossl_check"
"$SCRIPT_PATH" --user=$user;
}

function nomail() {
user=${1}
acct_verify
whmapi1 suspend_outgoing_email user=$user >>/dev/null
echo -e "The cPanel account \033[1;33m$user\033[0m have outgoing email suspended ";
}

function yesmail() {
user=${1}
acct_verify
whmapi1 unsuspend_outgoing_email user=$user >>/dev/null
echo -e "The cPanel account \033[1;33m$user\033[0m have outgoing email unsuspended ";
}

function enableshell() {
user=${1}
acct_verify
whmapi1 modifyacct user=$user shell=true >>/dev/null 
echo -e "The cPanel account \033[1;33m$user\033[0m have access shell enabled ";
}

function restrict_mailacct(){
user=${1}
domain=$(echo $user | cut -d@ -f2)
domain_verify
account=$(grep $domain /etc/trueuserdomains | cut -d: -f2 | head -1 | sed 's/ //g')
mail_verify

uapi --user=$account Email suspend_login email=$user >> /dev/null
uapi --user=$account Email suspend_incoming email=$user >> /dev/null
uapi --user=$account Email suspend_outgoing email=$user >> /dev/null

echo -e "The mail account \033[1;33m$user\033[0m are suspended"
}

function unrestrict_mailacct(){
user=${1}
domain=$(echo $user | cut -d@ -f2)
domain_verify
account=$(grep $domain /etc/trueuserdomains | cut -d: -f2 | head -1| sed 's/ //g')
mail_verify

uapi --user=$account Email unsuspend_login email=$user >> /dev/null
uapi --user=$account Email unsuspend_incoming email=$user >> /dev/null
uapi --user=$account Email unsuspend_outgoing email=$user >> /dev/null

echo -e "The mail account \033[1;33m$user\033[0m are unsuspended"
}

function changemail_password(){
user=${1}
domain=$(echo $user | cut -d@ -f2)
domain_verify
account=$(grep $domain /etc/trueuserdomains | cut -d: -f2 | head -1 | sed 's/ //g')
mail_verify

password=$(openssl rand 10 -base64)

uapi --user=$account Email passwd_pop email=$user password=$password domain=$domain >> /dev/null
echo -e "The mail account \033[1;33m$user\033[0m have a new password \033[1;33m$password\033[0m";
}

function checkmx(){
domain=${1}

maillocate_verify

echo -e "\nDNS Mx entries from $domain:"
whmapi1 listmxs domain=$domain | grep exchange:
}


