### TTL Fingerprinting:

    Windows: 128
    Linux: 64
    Solaris: 255
    Cisco: 255
    
### Ephemeral Port Ranges:

    1024-5000: Windows<=XP, FreeBSD<=4.11, Linux<=2.2
    49152-65535: FreeBSD>=5.0, Windows>=Vista, Apple MacOSX/IOS
    32768-61000: Linux>=2.4, Solaris
    10000-65535: FreeBSD>=8.0

## Packet Sniffing:

    Sniffing is done before any processing by networking stack
    Tools: tcpdump, wireshark (tshark), windump, snoop (Solaris)
    TTL Fingerprinting:  255=networking device, 128=Windows, 64=Unix/Linux

    TCPDump:
      ex. tcpdump -i any 'src host 1.2.3.4 and dst net 192.168.1.0/24 and ! tcp dst port 21' -nn [-e -s0] [-XXvvv]
        Options: 
            -r/-w read/write pcap file
            -i [any/eth0/...] interface
            -XXvvv show hex and ascii
            -e show link-level/MAC info
            -nn don't convert addresses
            -D show available interfaces
            -s 0 capture full contents
            -d view compiled filter
            -c packet count
            'expression'
        Modifiers:  ! or not; && or and; || or or
        Filters:
            Protocols:  ether/ip/ip6/icmp/arp/tcp/udp/dhcp/dns/ftp/ssh/telnet/...
            Layer 2/Ethernet:
                Address:  ether [src/dst] host ...  \\  ether multicast/broadcast
                    Destination OUI:  ether [0:4] & 0xffffff00 = 0x00005056
                    Source MAC Locally Administered:  ether[6] & 0x2 = 0x2
                Protocol (ex. EAPoL):  'ether proto 0x888e'
                Other:  vlan // ether[12:2] = 0x8100; ICMP types (icmp-echo, icmp-echoreply, etc.)
                Cisco devices:  'ether[20:2]=0x2000'
            Layer 3/IP:
                Address:  [src/dst] host ...  \\  [src/dst] net ...  \\  ip multicast/broadcast
                host ...  \\  dst host ...  \\  src host ...  \\  ip net ...  \\  host 192.168.11.110 and net 192.168.111.0/24
                Protocol:  [ip/ip6] proto 231
                    All ipv4 traffic:  ip
                All fragments of a fragmented packet:  ip[6] & 0x20 != 0 or ip[6:2] & 0x1FFF != 0
                TTL:  ip[8]=128
                ESP Traffic:  ip[9] = 50
            Layer 4:
                [tcp/udp] [src/dst] port ...  \\  portrange ...
                TCP Flags:  tcp-urg/tcp-ack/tcp-psh/tcp-rst/tcp-syn/tcp-fin

    Wireshark:
        Modifiers:  and or &&; or or ||; not or !
        Operators:  eq or ==; ne or !=; gt or >; lt or <; ge or >=; le or <=
        Filters:
            BPF syntax:  eth[0]==0xff  (instead of ether[0]=0xff); eth[12:2]==08:06; eth[0:6]==ff:ff:ff:ff:ff:ff
            Protocols:  ether/ip/ip6/icmp/arp/tcp/udp/dhcp/dns/ftp/ssh/telnet/...
            Layer 2/Ethernet:
                Address:  eth.[addr/dst/src]==...
                    Broadcast:  eth.dst==ff:ff:ff:ff:ff:ff
                    Multicast:  (eth.dst[0] & 1)
                ARP requests/replies:  arp.opcode==[1/2]
                ICMP Echo (Ping) Requests:  icmp.type==8 and icmp.code==0
            Layer 3/IP:
                Address:  ip.[addr/dest/src]==
                URL:  http.host=="host name"
                Hostname:  ip.host=hostname
            Layer 4:
                Protocol: tcp/udp
                Port:  [tcp/udp].[src/dst]port==443
                Flags:  tcp.flags.[syn/ack/reset/...]==[1/0]
                    ex. RST/ACK packets:  tcp.flags.reset==1 and tcp.flags.ack==1
            Other:
                DNS:
                    DNS standard queries:  dns.flags.response==none
                    DNS server hostname:  dns.flags.response==1, ...
                    DNS A Record response count:  dns.flags.response==1 and dns.qry.type==1
                    DNS standard reverse (PTR) lookup responses:  udp.dstport==53 and dns.flags.response==1 and dns.qry.type==12           
                    IP address of mountain.felidae.lab:  udp.dstport==53 and dns.resp.name==mountain.felidae.lab
                Cisco devices:  llc.cisco_pid == 0x2000
                FTP command of 'PWD':  ftp.command==PWD

    Snoop (Solaris):
        Modifiers:  and; or or ,; not or !
        Options:
            -r Don't resolve IPs 
            -d e1000g1 (device)
            -c Count
            [-i/-o filename]
            -V verbose summary
        Filters:
            [src/dst] [host/net/ipaddr/port/etheraddr "..."]
            [ethertype #]
                or [ip/ip6/arp/rarp/dhcp/etc.] 
            [udp, tcp, icmp, icmp6, ah, esp] 
            [broadcast/multicast]

## Networking Configuration:

    Add Route:
        *If can't reach host, try routing it to a different host on the network (from discovery)
        Unix: sysctl net.ipv4.ip_forward  (sysctl -w net.ipv4.ip_forward=1);  ip route add 172.10.1.0/24 [via 10.0.0.100  \\  dev eth1]  \\  route add 172.17.0.0/24 172.18.31.12
        Windows:  route add -p 192.168.103.0 mask 255.255.255.0 192.168.18.45 [metric 1]  \\  netsh interface ipv4 add route 192.168.103.0/24 "Local Area Connection 2" 192.168.18.45
    Delete Route:
        Unix:  ip route delete 172.10.1.0/24  \\  route del -net 172.17.0.0 netmask 255.255.255.128
        Windows:  route delete 192.168.103.0  \\  netsh interface ipv4 delete route 192.168.103.0/24 "Local Area Connection 2" 192.168.18.45
    Add ARP Entry:  arp -s 172.18.31.12 00:50:56:0D:01:12
        Other-network host (use interface MAC):  arp -si ens160 10.158.94.76 00:50:56:8e:61:39
        Delete:  arp -d 172.18.31.12
    Resolve DNS: Specific Server: dig @8.8.4.4 www.example.com  \\  Configured Nameserver: nslookup www.example.com  \\  host

    Windows:
        netsh dnsclient add dnsserver "Local Area Connection 2" 8.8.8.8
            netsh dnsclient delete dnsserver "Local Area Connection 2" 4.4.4.4
        nslookup www.google.com
        Discard DHCP configuration: ipconfig /release
        Reestablish DHCP config:  ipconfig /renew
        Flush DNS cache: ipconfig /flushdns
        ipconfig /registerdns
        Set IP address:  netsh interface ipv4 set address ....
        Change hostname:  wmic computersystem where name="%computername%" call rename name=newname
    Unix:
      Solaris <=10:
            Files:
                /etc/hostname.e1000g0
                /etc/hosts  (/etc/inet/hosts)
                /etc/inet/ipnodes  --ip addresses; later switched to /etc/inet/hosts
                /etc/nodename  (hostname)
                /etc/netmasks
                /etc/defaultrouter
                /etc/gateways  (add static route)  or  /etc/inet/static_routes
                /etc/resolv.conf        
        Change IP address:  ifconfig e1000g0 172.18.31.14 netmask 255.255.255.0 up           
            Bring interface down:  ifconfig e1000g0 down
            Change MAC address:  ifconfig e1000g0 ether 00:50:56:0D:01:14
            Enable DHCP:  ifconfig e1000g0 dhcp start            
            Disable DHCP:  ifconfig e1000g0 dhcp release
            Change hostname:  hostname newname
            Change Default Gateway:  route add default 172.18.31.253; route delete default 192.168.11.254
            Add route:  route add 172.17.0.0/25 172.18.31.12
            Delete route:  route delete 172.17.0.0/25 172.18.31.12
            Add static ARP entry:  arp -s 172.18.31.12 00:50:56:0D:01:12
            Delete ARP entry:  arp -d 172.18.31.12
            Change DNS: update /etc/resolv.conf       
            Reboot persistence:
                IP address:  Reboot persistence:  edit /etc/inet/hosts
                IP/mask:  echo -e '172.18.31.0\t255.255.255.0' >> /etc/netmasks
                Default gateway:  echo 172.18.31.253 > /etc/defaultrouter
                MAC address:  echo 'hamster ether 00:50:...' > /etc/hostname.e1000g0
                Enable dhcp:  touch /etc/dhcp.e1000g0
                Change hostname:  edit /etc/hosts, /etc/nodename
                Static routes:  echo '172.17.../25 172...' > /etc/inet/static_routes		
      RedHat and Linux:
            Files:
                /etc/sysconfig/network-scripts/ifcfg-eth0
                /etc/sysconfig/network (includes Hostname)
                /etc/hostname
                /etc/hosts
                /etc/sysconfig/network-scripts/route-eth0
                /etc/resolv.conf
            Change IP address:  ifconfig eth2 172.18.31.14 netmask 255.255.255.0 up  \\  ip addr add 192.168.11.222 dev eth0
          Delete IP address:  ip addr del 172.18.31.14/24 dev eth2
            Bring interface down:  ifconfig eth0 down
            Change MAC address:  ifconfig eth0 hw ether 00:50:56:0D:01:14
            Enable DHCP:  dhclient eth0           
            Disable DHCP:  dhclient -r eth0
            Change hostname:  hostname newname
            Change Default Gateway:  route add default gw 172.18.31.253
            Add route:  ip route add 172.10.1.0/24 [via 10.0.0.100  \\  dev eth1]  \\  route add -net 172.17.0.0 netmask 255.255.255.128 gw 172.18.31.12
            Delete route:  ip route delete 172.10.1.0/24  \\  route del -net 172.17.0.0 netmask 255.255.255.128
            Add static ARP entry:  arp -s 172.18.31.12 00:50:56:0D:01:12
          For off-network address:  arp -si ens160 10.158.94.76 00:50:56:8e:61:39
            Delete ARP entry:  arp -d 172.18.31.12
            Change DNS: update /etc/resolv.conf  
            Reboot persistence:
          Hostname: edit /etc/hostname and /etc/hosts
                IP address:  update /etc/sysconfig/network-scripts/ifcfg-eth0
                MAC:  add MACADDR=... to ^
                Update gateway and hostname in /etc/network and /etc/hostname and /etc/hosts
                Static routes:  echo '172.../25 via 172....' > /etc/sysconfig/network-scripts/route-eth0
                    also /etc/sysconfig/networking/devices and /etc/sysconfig/networking/profiles/default
          Gateway:  /etc/sysconfig/network-scripts/ifcfg-ens160
 
## Device Discovery:

    Basic Sniffing:
        tcpdump -i any -nn [not host/net ...]
        sudo snoop -r [not host/net ...] [-d e1000g1]
        Finding Gateway:
            Wireshark:  ip.src==192.168.1.2 && !(ip.dst==192.168.1.0/24) or  !(ip.dst==192.168.1.0/24)  ; note dest. Mac addr.
                then: eth.src==00:... && eth.type==0x0806
            TCPDump:  'src host 192.168.1.2 and not dst net 192.168.1.0/24'
                then:  'ether src host ... and ether [12:2]=0x0806'
    Ping Sweep:
        Unix:  for i in {1..254} ;do (ping -c 1 192.168.1.$i | grep "bytes from" &) ;done
        Windows:  for /L %i in (1,1,255) do @ping -n 1 -w 200 192.168.1.%i > nul && echo 192.168.1.%i is up.
        Solaris:  for i in {1..254} ;do (ping 192.168.1.$i 1 | grep "is alive" &) ;done
    Basic Nmap:  nmap 192.168.1.0/24 [-Pn/P0] [-p-]
    Netcat Scans:
        Scan 1 system for a range of ports using Netcat:
            for i in $(seq 1 65535); do nc -nvz -w 1 172.17.0.1 $i 2>&1; done | grep -v "refused"
            for i in {20..65535}; do nc -nzvw1 192.168.65.20 $i 2>&1 & done | grep -E 'succ|open$'
        Scan 1 system for a range of ports using /DEV/TCP:
            for p in {1..1023}; do(echo >/dev/tcp/10.0.0.104/$p) >/dev/null 2>&1 && echo "$p open"; done
        Scan a range of IPs for specific ports using Netcat:
            for i in {1..254}; do nc -nvzw1 192.168.65.$i 20-23 80 2>&1 & done | grep -E 'succ|open$'
    Test Connectivity:
      ping/arping/traceroute
        Check: netstat SYN status
      Bash /dev/tcp tool:
        echo a > /dev/tcp/192.168.11.13/22
          if no error: has connectivity, and port open
        *Banner grab:  bash -c "exec 3<>/dev/tcp/192.168.11.13/22; echo EOF>&3; cat<&3"
        Multiple/Port Scan:  portisopen(){ timeout 0.5s /bin/bash -c "echo EOF > /dev/tcp/$1/$2" 2>/dev/null || return 1; }; bannergrab(){ bash -c "exec 3<>/dev/tcp/$1/$2; echo EOF>&3; cat<&3"; }; common_ports=( 21 22 23 25 53 80 443 2222 8080 8443 9090 3306 10000 ); scan_common_ports(){ echo "<scan host=\"$1\"; date=\"$(date '+%Y-%m-%d %T')\">"; for port in ${common_ports[*]} ; do portisopen $1 $port && ( echo "<open port=$port>"; bannergrab $1 $port; echo "</open>" ); done; echo "</scan>"; }
          then:  scan_common_ports 192.168.1.2
    Unix Local Checks:
        ip nei / arp -an
        cat /etc/hosts
        getent hosts
        cat /etc/resolv.conf
        netstat -rn  \\  route print  \\  ip route show
        ifconfig -a  \\  ip a
        netstat -tanup
        iptables -nvL; iptables -t nat -nvL; iptables -t raw -nvL; iptables -t mangle -nvL
            Solaris:  ipfstat -io
        last; lastb; lastlog
        Samba:  nmblookup -A [connected IP]
    Windows Local Checks:  
        ipconfig /all
        arp -a
        ipconfig /displaydns | more
        netstat -rn  \\  route print
        netstat -anob
        systeminfo; wmic computersystem get domain; echo %userdomain%
        type C:\Windows\System32\drivers\etc\hosts
        netsh advfirewall firewall show rule profile=any name=all
        net use; net view
        nbtstat -rn
        SMB: lookup connected devices

 
