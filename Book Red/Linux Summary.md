    //Basics:
        id
        netstat -tanup
        ps -Hef
            //user sshing out or in?
        ls -tral / /home /home/* /root /tmp /var/log /opt
        ls -tral /root/.ssh /home/*/.ssh
        cat /root/.*history /home/*/.*history

    //Privesc:
        sudo -l
        linpeas.sh
        //Start PSPY Monitor...

    //Enumeration:
        last -F             //user sshing in?
        ls -tralR /var/*cron* /var/spool/cron* /etc/cron*
        cat /etc/passwd /etc/shadow
        find /home/ -name "id_rsa"
        find /home/ -iname "*id_rsa*"              //check even if not root
        ls -tral /root/.ssh /home/*/.ssh
        ls -tral /tmp/ssh*
        find / -iname *keytab* 2>/dev/null
        tail -100 /var/log/syslog
        egrep -i "password|passwd|secret" /var/log/syslog*
        ls -tral /etc /opt

    //Kerberos?
        realm list
        which ktutil klist kinit kvno
        env | grep KRB5CCNAME
        ls -tral /etc/krb*
        ls -tral /tmp/krb*
        sudo find / -iname *keytab* 2>/dev/null
        cat /etc/crontab; ls -tralR /etc/*cron* /var/spool/cron* /var/*cron*
        //see below for requesting tickets, using keytab files, etc.

    //Ansible?
        run "ansible" - see if it's a command
        check for /etc/ansible
        check /etc/passwd
        ls -tral /home
        grep -i ansible /var/log/* 2>/dev/null | wc -l
        find / -iname *ansible* 2>/dev/null
        find / -iname *playbook* 2>/dev/null
        grep -Ri "ansible_become_pass" /opt/playbooks/*

    //Artifactory?
        ps aux | grep -i artifactory