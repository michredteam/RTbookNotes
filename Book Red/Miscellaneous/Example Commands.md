
 **Curl:**
 
      -X - mode
      -H - request headers
      -d - data fields
      -i - show response headers
      Authenticate w/ API Key:  curl -i -H "Authorization: <key>" http://abc:8001/api/v1/apikey
          Upload file w/ Curl:  curl -F file.yml=@file.yml -H "Authorization: <key>" http://abc:8001/api/v1/process
      POSTing Data:
          curl -i -X 'POST' --data-binary 'id=guest' 'http://abc:8080/abc/RequestPasswordReset.jsp'
          curl -i -X POST -H "Content-Type: application/json" -d '{"url":"http://192.168.1.1"}' http://abc:8000/files/import
          curl -X POST -H "Content-Type: application/json" -d '{"url":"http://172.16.1.1:9000/api/render?url=http://192.168.1.1"}' http://abc:8000/files/import
          curl -i -X POST -H "Content-Type: application/json" -d '{"apikey":"<key>"}' http://abc:8000/render
          curl -i -X POST -H "apikey: <key>" http://abc:8000/render
          curl -i -X POST -H "apikey: <key>" -H "Content-Type: application/json" -d '{"url":"http://abc/render/url"}' http://abc:8000/render --output out.pdf
              Or via GET:  curl "http://abc:8000/render?url=http://abc/render/url&apikey=<key>"
          curl http://10.10.10.108/zabbix/api_jsonrpc.php -H "Content-Type: application/json-rpc" -d '{"jsonrpc":"2.0", "method":"user.login", "id":1, "auth":null, "params":{"user": "blah", "password": "blah"}}'
            curl -s http://10.10.10.108/zabbix/api_jsonrpc.php -H "Content-Type: application/json-rpc" -d '{"jsonrpc":"2.0", "method":"user.get", "id":1, "auth":"blah", "params":{"output": "extend"}}' | jq .
   
**Find:**

      Find file by type:  find / -type f -exec file {} \;|grep -i python
      Find a world writeable directory:  find /var/www/html/ -type d -perm -o+w
      By Modification Date:  find / -type f -newer /tmp/start -not -newer /tmp/end  \\  find / -type f -newermt "YYYY-MM-DD" ! -newermt "YYYY-MM-DD"
          (modified between the time stamps for the other files)
          By Access Date:  find / -type f -neweram /tmp/start -not -neweram /tmp/end  \\  find / -type f -anewermt "YYYY-MM-DD" ! -anewermt "YYYY-MM-DD"  \\  find / -type f -anewer /root/file1 ! -anewer /root/file2
              (accessed between the mod. time stamps for the other files)
          Older than 30 days:  find /root/metrics/ -type f -mtime +30 -exec rm {} \;
      find / -name sample.txt
      find /etc -name *.conf
      find / -name sample.txt -exec rm -i {} \;
      find ./ -perm 664 -type f
      find / -iname pass -type f
      Search text in multiple files:  find ./ -type f -name "*.txt" -exec grep -i 'password'  {} \;
      find /var -name \*.log -exec wc -l \{\} \;  -->  wc -l file1, wc -l file2, wc -l file3
      or:  find /var -name \*.log -exec wc -l \{\} \;\+  -->  wc -l file1 file2 file3
      Test if string in files:  find /root/Sorgan/ -type f -print0 [-maxdepth 1]| xargs -0 grep -l "grogu"
      Find files modified by user during recent session:  last -F; then: find -type f -newermt "" ! -newermt ""  \\  touch -t yymmddhhmm.ss and find -type f -newer /root/file1 ! -newer /root/file2

**Scripting Examples:**

      cat /var/log/access_log|grep 'GET /child HTTP'|cut -d ' ' -f 1|sort|uniq|wc -l
      cat /var/log/access_log| cut -d 'T' -f 2|cut -d ' ' -f 2|sort|uniq|wc -l
      for i in $(awk {'print $1'} /var/log/access_log | sort | uniq); do echo $i && grep $i /var/log/access_log | awk -F\" {'print $5'}; done
      awk -F\" '{print $2 $6}' access_log-20190218|grep -i "GET /contact-us.html HTTP"|sort|uniq
      awk -F\" '{print $1 $2 $6}' access_log-20190218|grep -i "13/Feb/2019"|grep -i "GET /contact-us.html HTTP"|awk -F "HTTP" '{print $2}'|sort|uniq
      cat /var/log/iptables.log|awk -F 'SRC=| DST=' '{print $2}'|sort|uniq -c
      cat /var/log/iptables.log|awk -F 'MAC=| DST=' '{print $2}'|sort -k2|uniq -c
      Find string in certain files:  grep -l 'ops\.local' $(find /etc -name '*.conf') | xargs -I {} cat {} > /tmp/outfile

**Miscellaneous:**

      User Crontabs:  for user in $(getent passwd | awk -F ':' '{print $1}' ); do echo $user; crontab -u $user -l  2>/dev/null; done|more
      View processes writing to files:  lsof | awk '$4~/w/ && $5~/REG/ && $9!~/^.dev|^.proc|^.run/{print $0}'
      Monitoring for Ping Payload Success:  sudo tcpdump -i tun0 'icmp and host <tgt ip>'  

**Tar:**

      Recreates full directory path by default when untarring a directory
        put all files in current directory instead:  tar -cf /tmp/backup/run1.tar -C /var/run .
      tar -cvf /tmp/backup/run.tar /var/run
      ex. Extract 17th file of archive:  tar -xf run1.tar `tar -tf run1.tar | head -n 17 | tail -n 1`
     
**Docker:**
    sudo docker-compose -f concord-1.43.0/docker-compose.yml down
    sudo docker-compose -f concord-1.83.0/docker-compose.yml up -d
    docker-compose down
    TEMPLATING_ENGINE=ejs docker-compose up
    Interactive CLI & Remote Debugging:  docker-compose -f ~/chips/docker-compose.yml exec chips node --inspect=0.0.0.0:9228
    View logs:  docker-compose -f ~/chips/docker-compose.yml logs chips
    View libraries/dependencies:  docker-compose -f ~/chips/docker-compose.yml run chips npm list -prod -depth 1
    TEMPLATING_ENGINE=ejs docker-compose up &     
