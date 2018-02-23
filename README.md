# SshWeakPasswordAudit
a small tool for auditting weak ssh password

#to find all ssh ports, use zmap as:
zmap -p 22 -o ssh_hosts_found.txt -w ipsubnets.txt -B 50M -i eth0 -M tcp_synscan --disable-syslog 

#transrate hosts to host:port
sed "s/$/:22/g" ssh_hosts_found.txt > ssh_targets.txt

#run weakpassword audit prog
./sshbrute -i ssh_targets.txt -d ssh_userpasswords.txt -o ssh_weakpasswd_found.txt -l sshbrute.log -t 500

#verify
python sshverify.py -l SshVerify.log -i ssh_weakpasswd_found.txt -o ssh_weakpasswd_verified.txt
