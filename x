#!/usr/bin/env bash

set -euo pipefail

# --- 1) common stacks ---

sudo apt install pamu2fcfg libpam-u2f

sudo -u dev pamu2fcfg  > /etc/conf
sudo chmod 600 /etc/conf

cat >/etc/pam.d/common-auth <<'EOF'
#%PAM-1.0
auth   sufficient  pam_u2f.so authfile=/etc/conf
auth   [success=1 default=ignore] pam_unix.so try_first_pass
auth   requisite   pam_deny.so
auth   required    pam_permit.so
EOF
cat >/etc/pam.d/common-account <<'EOF'
#%PAM-1.0
account required pam_unix.so
EOF
cat >/etc/pam.d/common-session <<'EOF'
#%PAM-1.0
session required pam_limits.so
session required pam_env.so
session optional pam_systemd.so
session required pam_unix.so
EOF
cat >/etc/pam.d/common-session-noninteractive <<'EOF'
#%PAM-1.0
session required pam_limits.so
session required pam_env.so
session optional pam_systemd.so
session required pam_unix.so
EOF
cat >/etc/pam.d/common-password <<'EOF'
#%PAM-1.0
password [success=1 default=ignore] pam_unix.so obscure use_authtok try_first_pass sha512
password requisite pam_deny.so
password required  pam_permit.so
EOF
cat >/etc/pam.d/lightdm <<'EOF'
#%PAM-1.0
auth      requisite pam_nologin.so
auth      required  pam_u2f.so authfile=/etc/conf
auth      include   common-auth
account   include   common-account
session   include   common-session
password  include   common-password
EOF
cat >/etc/pam.d/sudo <<'EOF'
#%PAM-1.0
auth      sufficient pam_u2f.so authfile=/etc/conf
auth      required   pam_unix.so
account   required   pam_unix.so
password  required   pam_unix.so
session   required   pam_limits.so
session   required   pam_env.so
session   required   pam_unix.so
EOF
cat >/etc/pam.d/sudo-i <<'EOF'
#%PAM-1.0
auth      required   pam_u2f.so authfile=/etc/conf
auth      required   pam_unix.so
account   required   pam_unix.so
password  required   pam_unix.so
session   required   pam_limits.so
session   required   pam_env.so
session   required   pam_unix.so
EOF
cat >/etc/pam.d/sshd <<'EOF'
#%PAM-1.0
auth      required   pam_u2f.so authfile=/etc/conf
auth      required   pam_unix.so
account   required   pam_unix.so
password  required   pam_unix.so
session   required   pam_limits.so
session   required   pam_env.so
session   required   pam_unix.so
EOF
cat >/etc/pam.d/su <<'EOF'
#%PAM-1.0
auth      required   pam_u2f.so authfile=/etc/conf
auth      required   pam_unix.so
account   required   pam_unix.so
password  required   pam_unix.so
session   required   pam_limits.so
session   required   pam_env.so
session   required   pam_unix.so
EOF
cat >/etc/pam.d/su-l <<'EOF'
#%PAM-1.0
auth      required   pam_u2f.so authfile=/etc/conf
auth      required   pam_unix.so
account   required   pam_unix.so
password  required   pam_unix.so
session   required   pam_limits.so
session   required   pam_env.so
session   required   pam_unix.so
EOF
cat >/etc/pam.d/other <<'EOF'
#%PAM-1.0
auth      requisite pam_securetty.so
auth      required   pam_unix.so
auth      required   pam_warn.so
auth      required   pam_deny.so
account   required   pam_unix.so
account   required   pam_warn.so
account   required   pam_deny.so
password  required   pam_unix.so
password  required   pam_warn.so
password  required   pam_deny.so
session   required   pam_unix.so
session   required   pam_warn.so
session   required   pam_deny.so
EOF
cat >/etc/pam.d/login <<'EOF'
#%PAM-1.0
auth      requisite pam_securetty.so
auth      include   common-auth
account   include   common-account
session   include   common-session
password  include   common-password
EOF

# === FIREWALLS ===
cat >/etc/nftables.conf <<EOF
flush ruleset

table ip filter {
  chain input {
    type filter hook input priority filter; policy drop;
    iifname "lo" accept
    ct state invalid drop
    ct state established,related accept
    iifname "wg0" accept
  }

  chain forward {
    type filter hook forward priority filter; policy drop;
  }

  chain output {
    type filter hook output priority filter; policy drop;
    oifname "lo" accept
    ct state invalid drop
    ct state established,related accept
    udp dport 51820 accept
    udp dport 53 accept
    tcp dport 443 accept
    tcp dport 80 accept

  }
}

EOF

# === 1. SYSTEM UPDATE AND ESSENTIALS ===
sudo echo 'Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";' >> /etc/apt/apt.conf.d/50unattended-upgrades
sudo echo 'APT::Get::AllowUnauthenticated "false";' >> /etc/apt/apt.conf.d/98-hardening
sudo echo 'Acquire::http::AllowRedirect "false";' >> /etc/apt/apt.conf.d/98-hardening
sudo echo 'APT::Install-Suggests "false";' >> /etc/apt/apt.conf.d/98-hardening 
sudo echo 'APT::Install-Recommends "false";' >> /etc/apt/apt.conf.d/98-hardening 
sudo apt update
sudo apt purge -y apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra
sudo apt install -y curl git apparmor rsyslog chrony apparmor-utils apparmor-profiles apparmor-profiles-extra apt-listbugs apt-listchanges needrestart debsecan debsums acct wget gnupg lsb-release apt-transport-https git unzip patch tar pcscd pulseaudio curl git wget rkhunter chkrootkit lynis tcpd macchanger  unhide tcpd haveged rng-tools jitterentropy-rngd --no-install-recommends --no-suggests


# === REMOVE UNNECESSARY ACCOUNTS/GROUPS ===
sudo groupdel avahi --force
sudo groupdel _flatpak --force
sudo groupdel _ssh --force
sudo groupdel bluetooth --force
sudo groupdel irc --force
sudo groupdel kvm --force
sudo groupdel nm-openconnect --force
sudo groupdel nm-openvpn --force
sudo groupdel sambashare --force
sudo groupdel scanner --force
sudo groupdel voice --force
sudo groupdel vboxsf --force
sudo groupdel games --force
sudo groupdel colord --force
sudo userdel sshd
sudo userdel tss
sudo userdel usbmux
sudo userdel dnsqmasq
sudo userdel nobody
sudo userdel statd
sudo userdel hplip
sudo userdel colord
sudo userdel _rpc
sudo userdel avahi
sudo userdel games
sudo userdel irc
sudo userdel list
sudo userdel news
sudo userdel uucp

  sed -i 's/^# End of file*//' /etc/security/limits.conf
  { echo '* hard maxlogins 1'
    echo '* hard core 0'
    echo '* soft core  0''
    echo '* hard nproc 100'
    echo '# End of file'
  } >> /etc/security/limits.conf
  echo "ProcessSizeMax=0
  Storage=none" >> /etc/systemd/coredump.conf
  echo "ulimit -c 0" >> /etc/profile


sudo touch /etc/securetty
sudo chown  root:root /etc/securetty
sudo chmod  400 /etc/securetty
sudo passwd -l root
sudo echo "needs_root_rights = no" >> /etc/X11/Xwrapper.config
sudo dpkg-reconfigure xserver-xorg-legacy
sudo echo "multi on
      order hosts" > /etc/host.conf
sudo echo "session optional pam_umask.so umask=077" >> /etc/pam.d/common-session 
sudo echo "session optional pam_umask.so umask=077" >> /etc/pam.d/common-session-noninteractive
sed -i -e 's/^DIR_MODE=.*/DIR_MODE=0750/' -e 's/^#DIR_MODE=.*/DIR_MODE=0750/' /etc/adduser.conf
sed -i -e 's/^DSHELL=.*/DSHELL=\/usr\/sbin\/nologin/' -e 's/^#DSHELL=.*/DSHELL=\/bin\/false/' /etc/adduser.conf
sed -i -e 's/^USERGROUPS=.*/USERGROUPS=yes/' -e 's/^#USERGROUPS=.*/USERGROUPS=yes/' /etc/adduser.conf
sed -i 's/^SHELL=.*/SHELL=\/usr\/sbin\/nologin/' /etc/default/useradd
sed -i 's/^# INACTIVE=.*/INACTIVE=30/' /etc/default/useradd
sed -i 's/^.*LOG_OK_LOGINS.*/LOG_OK_LOGINS yes/' /etc/login.defs
sed -i 's/^UMASK*/UMASK 077/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 60/' /etc/login.defs
sed -i 's/DEFAULT_HOME.*/DEFAULT_HOME no/' /etc/login.defs
sed -i 's/ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs
sed -i 's/USERGROUPS_ENAB.*/USERGROUPS_ENAB no/' /etc/login.defs
sed -i 's/^#.*SHA_CRYPT_MIN_ROUNDS .*/SHA_CRYPT_MIN_ROUNDS 10000/' /etc/login.defs
sed -i 's/^#.*SHA_CRYPT_MAX_ROUNDS .*/SHA_CRYPT_MAX_ROUNDS 65536/' /etc/login.defs
sed -i 's/umask 027/umask 077/g' /etc/init.d/rc
echo "umask 077" >> /etc/profile
echo "umask 077" >> /etc/bash.bashrc
echo -e 'TMOUT=300' > '/etc/profile.d/autologout.sh'
echo "ALL: LOCAL, 127.0.0.1" >> /etc/hosts.allow
echo "ALL: ALL" > /etc/hosts.deny
chmod 644 /etc/hosts.allow
chmod 644 /etc/hosts.deny
 

sudo sed -i 's|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT="slab_nomerge slub_debug=FZ init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 pti=on vsyscall=none debugfs=off oops=panic module.sig_enforce=1 lockdown=confidentiality mce=0 quiet loglevel=0 ipv6.disable=1 spectre_v2=on spec_store_bypass_disable=on tsx=off tsx_async_abort=full,nosmt mds=full,nosmt l1tf=full,force nosmt=force kvm.nx_huge_pages=force quiet loglevel=0 apparmor=1 security=apparmor"|' /etc/default/grub
sudo update-grub
sudo chown root:root /etc/default/grub
sudo chmod 640 /etc/default/grub 

sudo mkdir /etc/ssh
sudo tee  /etc/ssh/sshd_config > /dev/null <<EOF
X11UseLocalhost no
X11Forwarding no
X11DisplayOffset 10
VersionAddendum none
UsePAM no
UseDNS no
TCPKeepAlive no
SyslogFacility AUTH
StrictModes yes
RekeyLimit 512Ms+6h
Protocol 2
PrintMotd no
PrintLastLog no
Port 1212
PermitUserRC no
PermitUserEnvironment no
PermitTunnel no
PermitTTY no
PermitRootLogin no
PermitEmptyPasswords no
PasswordAuthentication no
MaxSessions 0
MaxAuthTries 0
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
LogLevel VERBOSE
LoginGraceTime 60
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,group-exchange-sha256
KerberosTicketCleanup no
KerberosOrLocalPasswd no
KerberosGetAFSToken no
KerberosAuthentication no
KbdInteractiveAuthentication no
IgnoreUserKnownHosts yes
IgnoreRhosts yes
HostbasedAuthentication no
GSSAPIKeyExchange no
GSSAPIAuthentication no
GatewayPorts none
Compression no
ClientAliveInterval 0
ClientAliveCountMax 0
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
DenyUsers all
DenyGroups all
DenyHosts all
ChrootDirectory none
ChallengeResponseAuthentication no
Banner /etc/issue.net
AuthorizedPrincipalsFile none
AuthorizedKeysCommandUser
AuthorizedKeysCommand none
AllowUsers none
AllowTcpForwarding no
AllowStreamLocalForwarding no
AllowGroups none
AllowAgentForwarding no
EOF

sudo rc-service ssh stop
sudo rc-service sshd stop
sudo apt remove -y openssh* ssh*


sudo echo "
Unauthorized access to this server is prohibited.
All connections are monitored and recorded.
Legal action will be taken. Please disconnect now.
" >> /etc/motd  
  
sudo echo "
Unauthorized access to this server is prohibited.
All connections are monitored and recorded.
Legal action will be taken. Please disconnect now.
" >> /etc/issue
  
sudo echo "
Unauthorized access to this server is prohibited.
All connections are monitored and recorded.
Legal action will be taken. Please disconnect now.
" >> /etc/issue.net

cat > /etc/modprobe.d/harden.conf << 'EOF'
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
install ax25 /bin/false
install netrom /bin/false
install x25 /bin/false
install rose /bin/false
install decnet /bin/false
install econet /bin/false
install af_802154 /bin/false
install ipx /bin/false
install appletalk /bin/false
install psnap /bin/false
install p8023 /bin/false
install p8022 /bin/false
install can /bin/false
install atm /bin/false
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
install squashfs /bin/false
install udf /bin/false
install cifs /bin/false
install nfs /bin/false
install nfsd /bin/false
install nfsv3 /bin/false
install nfsv4 /bin/false
install lockd /bin/false
install ksmbd /bin/false
install gfs2 /bin/false
install bluetooth /bin/false
install btusb /bin/false
install uvcvideo /bin/false
install firewire-core /bin/false
install thunderbolt /bin/false
install usb-storage /bin/false
blacklist dccp
blacklist sctp
blacklist rds
blacklist tipc
blacklist ax25
blacklist netrom
blacklist x25
blacklist rose
blacklist decnet
blacklist econet
blacklist af_802154
blacklist ipx
blacklist appletalk
blacklist psnap
blacklist p8023
blacklist p8022
blacklist can
blacklist atm
blacklist cramfs
blacklist freevxfs
blacklist jffs2
blacklist hfs
blacklist hfsplus
blacklist squashfs
blacklist udf
blacklist cifs
blacklist nfs
blacklist nfsd
blacklist nfsv3
blacklist nfsv4
blacklist lockd
blacklist ksmbd
blacklist gfs2
blacklist bluetooth
blacklist btusb
blacklist uvcvideo
blacklist firewire-core
blacklist thunderbolt
blacklist usb-storage
EOF

rm -r /etc/sysctl.d
rm -r /usr/lib/sysctl.d
echo "dev.tty.ldisc_autoload=0
fs.protected_fifos=2
fs.protected_hardlinks=1
fs.protected_symlinks=1
fs.protected_regular=1
fs.suid_dumpable=0
kernel.modules_disabled=0
kernel.core_pattern=|/bin/false
kernel.core_uses_pid=1
kernel.dmesg_restrict=1
kernel.kptr_restrict=2
kernel.panic=60
kernel.panic_on_oops=60
kernel.perf_event_paranoid=3
kernel.randomize_va_space=2
kernel.sysrq=0
kernel.unprivileged_bpf_disabled=1
kernel.unprivileged_userns_clone=1
kernel.yama.ptrace_scope=3
kernel.kexec_load_disabled=1
net.core.bpf_jit_harden=2
net.ipv4.tcp_sack=0
net.ipv4.tcp_dsack=0
net.ipv4.tcp_fack=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.ip_forward=0
net.ipv4.tcp_rfc1337=1
net.ipv4.tcp_syn_retries=5
net.ipv4.tcp_synack_retries=2
net.ipv4.tcp_syncookies=1
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.default.log_martians=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.default.shared_media=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.shared_media=0
net.ipv6.conf.default.accept_ra=0
net.ipv6.conf.default.accept_ra_defrtr=0
net.ipv6.conf.default.accept_ra_pinfo=0
net.ipv6.conf.default.accept_ra_rtr_pref=0
net.ipv6.conf.default.accept_redirects=0
net.ipv6.conf.default.accept_source_route=0
net.ipv6.conf.default.autoconf=0
net.ipv6.conf.default.dad_transmits=0
net.ipv6.conf.default.max_addresses=0
net.ipv6.conf.default.router_solicitations=0
net.ipv6.conf.eth0.accept_ra_rtr_pref=0
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.all.accept_source_route=0
net.ipv6.conf.all.forwarding=0
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
vm.mmap_rnd_bits=32
vm.mmap_rnd_compat_bits=16" > /etc/sysctl.conf
sysctl --system

sudo chmod 700 /root
sudo chown root:root /boot 
sudo chown root:root /etc 
sudo chown root:root /usr 
sudo chown root:root /var 
sudo chown root:root /sbin 
sudo chown root:root /bin
sudo chmod 0700 /boot
sudo chown root:root /boot/grub/grub.cfg
sudo chmod 0700 /boot/grub/grub.cfg
sudo chmod 0700 /boot
sudo chown root:root /etc/nftables.conf
sudo chmod 0700 /etc/nftables.conf
sudo chown dev /home/dev
sudo chmod 0700 /home/dev
sudo chown root:root /etc/hosts.allow
sudo chmod 0640 /etc/hosts.allow
sudo chown root:root /etc/hosts.deny
sudo chmod 0640 /etc/hosts.deny
sudo chown root:root /etc/passwd
sudo chmod 0644 /etc/passwd
sudo chown root:shadow /etc/shadow
sudo chmod 0640 /etc/shadow
sudo chown root:root /etc/group
sudo chmod 0644 /etc/group
sudo chown root:shadow /etc/gshadow
sudo chmod 0640 /etc/gshadow
sudo chown root:root /etc/security/opasswd
sudo chmod 0600 /etc/security/opasswd
sudo chown root:root /etc/passwd-
sudo chmod 0600 /etc/passwd-
sudo chown root:root /etc/shadow-
sudo chmod 0600 /etc/shadow-
sudo chown root:root /etc/group-
sudo chmod 0600 /etc/group-
sudo chown root:root /etc/gshadow-
sudo chmod 0600 /etc/gshadow-
sudo chown root:adm /var/log
sudo chmod -R 0640 /var/log
sudo chown root:root /etc/ssh/sshd_config
sudo chmod 0600 /etc/ssh/sshd_config
sudo chown root:root /etc/ssh/ssh_config
sudo chmod 0600 /etc/ssh/ssh_config
sudo chown root:root /etc/sudoers
sudo chmod 0440 /etc/sudoers
sudo find / -perm -4000 -o -perm -2000 -exec sudo chmod a-s {} \; 2>/dev/null
sudo find / -perm -4000 -exec sudo chmod u-s {} \;
sudo find / -perm -4000 -exec sudo chmod g-s {} \;
sudo find / -perm -2000 -exec sudo chmod u-s {} \;
sudo find / -perm -2000 -exec sudo chmod g-s {} \;
sudo chmod u+s /usr/bin/sudo



chmod o-rx /usr/bin/as
sudo chattr +i /etc/fstab
sudo chattr +i /etc/adduser.conf
sudo chattr +i /etc/group
sudo chattr +i /etc/group-
sudo chattr +i /etc/hosts
sudo chattr +i /etc/host.conf
sudo chattr +i /etc/hosts.allow
sudo chattr +i /etc/hosts.deny
sudo chattr +i /etc/login.defs
sudo chattr -R +i /etc/default
sudo chattr +i /etc/passwd
sudo chattr +i /etc/passwd-
sudo chattr +i /etc/securetty
sudo chattr -R +i /etc/security
sudo chattr +i /etc/gshadow-
sudo chattr +i /etc/gshadow
sudo chattr -R +i /etc/ssh
sudo chattr -R +i /etc/sudoers.d
sudo chattr +i /root/.bashrc
sudo chattr +i /etc/shadow
sudo chattr +i /etc/shadow-
sudo chattr +i /etc/shells
sudo chattr -R +i /etc/pam.d
sudo chattr +i /etc/sysctl.conf
sudo chattr -R +i /etc/modprobe.d
sudo chattr +i /etc/services
sudo chattr +i /etc/sudoers



