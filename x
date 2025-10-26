#!/usr/bin/env bash

set -euo pipefail

mount /usr -o remount,rw /usr
mount /usr -o remount,rw /boot

# PRE CONFIG/AUDIT
echo 'APT::Get::AllowUnauthenticated "false";' >> /etc/apt/apt.conf.d/98-hardening
echo 'APT::Install-Suggests "false";' >> /etc/apt/apt.conf.d/98-hardening 
echo 'APT::Install-Recommends "false";' >> /etc/apt/apt.conf.d/98-hardening 
apt update
apt purge -y  zram* yad* pci* papirus* orca* nfs* network-manager* pmount* libspa-0.2-bluetooth libspa-0.2-libcamera libpocketsphinx3 libjansson4 acpi* anacron* avahi* atmel* bc bind9* dns* fastfetch fonts-noto* fprint* isc-dhcp* lxc* docker* podman* xen* bochs* uml* vagrant* libssh* ssh* openssh* acpi* samba* winbind* qemu* libvirt* virt* cron* avahi* cup* print* rsync* virtual* sane* rpc* bind* nfs* blue* pp* spee* espeak* mobile* wireless* bc perl dictionaries-common doc-debian emacs* ethtool iamerican ibritish ienglish-common inet* ispell task-english util-linux-locales wamerican tasksel* vim*


# FIREWALL (MULLVAD REQUIRED)
apt install iptables iptables-persistent netfilter-persistent
systemctl enable netfilter-persistent
service netfilter-persistent start
sudo iptables -F
sudo iptables -X
sudo iptables -Z
sudo iptables -t nat -F
sudo iptables -t nat -X
sudo iptables -t nat -Z
sudo iptables -t mangle -F
sudo iptables -t mangle -X
sudo iptables -t mangle -Z
sudo iptables -P INPUT DROP
sudo iptables -P OUTPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
sudo iptables -A OUTPUT -m conntrack --ctstate INVALID -j DROP
sudo iptables -A OUTPUT -o eth0 -p udp --dport 51820 -j ACCEPT
sudo iptables -A INPUT -i wg0-mullvad -j ACCEPT
sudo iptables -A OUTPUT -o wg0-mullvad -j ACCEPT
sudo iptables -A OUTPUT -o wg0-mullvad -p udp --dport 53 -j ACCEPT
sudo iptables -A OUTPUT -o wg0-mullvad -p tcp --dport 80 -j ACCEPT 
sudo iptables -A OUTPUT -o wg0-mullvad -p tcp --dport 443 -j ACCEPT
sudo ip6tables -F
sudo ip6tables -X
sudo ip6tables -Z
sudo ip6tables -P INPUT DROP
sudo ip6tables -P OUTPUT DROP
sudo ip6tables -P FORWARD DROP
sudo netfilter-persistent save
sudo systemctl enable netfilter-persistent

install -d /etc/apt/preferences.d
cat >/etc/apt/preferences.d/deny-ssh.pref <<'EOF'
Package: openssh*
Pin: release *
Pin-Priority: -1

Package: dropbear*
Pin: release *
Pin-Priority: -1

Package: ssh*
Pin: release *
Pin-Priority: -1

Package: tinyssh*
Pin: release *
Pin-Priority: -1

Package: qemu*       
Pin: release *
Pin-Priority: -1

Package: libvirt*
Pin: release *
Pin-Priority: -1

Package: uml*
Pin: release *
Pin-Priority: -1

Package: virt*
Pin: release *
Pin-Priority: -1

Package: avahi*
Pin: release *
Pin-Priority: -1

Package: samba*
Pin: release *
Pin-Priority: -1

Package: pmount*
Pin: release *
Pin-Priority: -1

Package: sane*
Pin: release *
Pin-Priority: -1

Package: pp*
Pin: release *
Pin-Priority: -1

Package: blue*
Pin: release *
Pin-Priority: -1

Package: rpc*
Pin: release *
Pin-Priority: -1

Package: nfs*
Pin: release *
Pin-Priority: -1

Package: cup*
Pin: release *
Pin-Priority: -1

Package: anacron*
Pin: release *
Pin-Priority: -1

Package: exim*
Pin: release *
Pin-Priority: -1

Package: print*
Pin: release *
Pin-Priority: -1

Package: vagrant*
Pin: release *
Pin-Priority: -1

Package: lxc*
Pin: release *
Pin-Priority: -1

Package: docker*
Pin: release *
Pin-Priority: -1

Package: podman*
Pin: release *
Pin-Priority: -1

Package: xen*
Pin: release *
Pin-Priority: -1

Package: bochs*
Pin: release *
Pin-Priority: -1

Package: gnustep*
Pin: release *
Pin-Priority: -1

Package: sendmail*
Pin: release *
Pin-Priority: -1

Package: mobile*
Pin: release *
Pin-Priority: -1

Package: wireless*
Pin: release *
Pin-Priority: -1

Package: inet*
Pin: release *
Pin-Priority: -1

Package: vagrant*
Pin: release *
Pin-Priority: -1
EOF

#INSTALL APPLICATIONS
apt update 
apt install -y pamu2fcfg libpam-u2f rsyslog chrony unzip patch lynis macchanger unhide auditd fonts-liberation gnome-terminal gnome-brave-icon-theme breeze-gtk-theme bibata* tcpd libxfce4ui-utils thunar xfce4-panel xfce4-session xfce4-settings xfce4-terminal xfconf xfdesktop4 xfwm4 xserver-xorg xinit xserver-xorg-legacy xfce4-pulse* xfce4-whisk* opensnitch* python3-opensnitch*

#U2F
#mkdir /home/dev/.config
pamu2fcfg -u dev > /home/dev/.config/default
chmod 600 /home/dev/.config/default
install -o root -g root -m 600 /home/dev/.config/default /etc/conf
chattr +i /home/dev/.config/default
chattr +i /etc/conf

cat >/etc/pam.d/chfn <<'EOF'
#%PAM-1.0
auth      sufficient  pam_rootok.so
auth      include     common-auth
account   include     common-account
session   include     common-session
EOF

cat >/etc/pam.d/chpasswd <<'EOF'
#%PAM-1.0
password  include     common-password
EOF

cat >/etc/pam.d/chsh <<'EOF'
#%PAM-1.0
auth      required    pam_shells.so
auth      sufficient  pam_rootok.so
auth      include     common-auth
account   include     common-account
session   include     common-session
EOF

cat >/etc/pam.d/common-account <<'EOF'
#%PAM-1.0
account   required    pam_faillock.so 
account   [success=1  new_authtok_reqd=done default=ignore]  pam_unix.so 
account   requisite   pam_deny.so
account   required    pam_permit.so
EOF

cat >/etc/pam.d/common-password <<'EOF'
#%PAM-1.0
password  requisite   pam_pwquality.so retry=3
password  [success=1  default=ignore]  pam_unix.so obscure use_authtok try_first_pass yescrypt
password  requisite   pam_deny.so
password  required    pam_permit.so
EOF

cat >/etc/pam.d/common-auth <<'EOF'
#%PAM-1.0
auth      sufficient  pam_u2f.so authfile=/etc/conf
auth      [success=1  default=ignore]  pam_unix.so try_first_pass
auth      requisite   pam_deny.so
auth      required    pam_permit.so
EOF


cat >/etc/pam.d/common-session <<'EOF'
#%PAM-1.0
session   required    pam_limits.so
session   optional    pam_umask.so umask=077
session   required    pam_unix.so
EOF

cat >/etc/pam.d/common-session-noninteractive <<'EOF'
#%PAM-1.0
session   required    pam_limits.so
session   optional    pam_umask.so umask=077
session   required    pam_unix.so
EOF

cat >/etc/pam.d/sudo <<'EOF'
#%PAM-1.0
auth      include     common-auth
account   include     common-account
password  include     common-password
session   include     common-session
EOF

cat >/etc/pam.d/sudo-i <<'EOF'
#%PAM-1.0
auth      include     common-auth
account   include     common-account
password  include     common-password
session   include     common-session
EOF

cat >/etc/pam.d/sshd <<'EOF'
#%PAM-1.0
auth      include     common-auth
account   include     common-account
password  include     common-password
session   include     common-session
EOF

cat >/etc/pam.d/su <<'EOF'
#%PAM-1.0
auth      include     common-auth
account   include     common-account
password  include     common-password
session   include     common-session
EOF

cat >/etc/pam.d/su-l <<'EOF'
#%PAM-1.0
auth      include     common-auth
account   include     common-account
password  include     common-password
session   include     common-session
EOF

cat >/etc/pam.d/other <<'EOF'
#%PAM-1.0
auth      required    pam_deny.so
account   required    pam_deny.so
password  required    pam_deny.so
session   required    pam_deny.so
EOF

cat >/etc/pam.d/lightdm <<'EOF'
#%PAM-1.0
auth      requisite   pam_nologin.so
auth      include     common-auth
account   include     common-account
session   required    pam_limits.so
session   required    pam_loginuid.so
session   include     common-session
password  include     common-password
EOF

cat >/etc/pam.d/lightdm-greeter <<'EOF'
#%PAM-1.0
auth      required    pam_permit.so
account   required    pam_permit.so
password  required    pam_deny.so
session   required    pam_unix.so
session   include     common-session
EOF

cat >/etc/pam.d/login <<'EOF'
#%PAM-1.0
auth      optional    pam_faildelay.so delay=3000000
auth      requisite   pam_nologin.so
session   required    pam_loginuid.so
auth      include     common-auth
account   required    pam_access.so
session   required    pam_limits.so
account   include     common-account
session   include     common-session
password  include     common-password
EOF

cat >/etc/pam.d/newusers <<'EOF'
#%PAM-1.0
password  include     common-password
EOF

cat >/etc/pam.d/passwd <<'EOF'
#%PAM-1.0
password  include     common-password
EOF

cat >/etc/pam.d/runuser <<'EOF'
#%PAM-1.0
auth	     sufficient  pam_rootok.so
session	  required    pam_limits.so
session	  required    pam_unix.so
EOF

cat >/etc/pam.d/runuser-l <<'EOF'
#%PAM-1.0
auth	     include     runuser
session	  include     runuser
EOF

apt install -y git curl wget apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra
git clone https://github.com/ovh/debian-cis.git && cd debian-cis
cp debian/default /etc/default/cis-hardening
sed -i "s#CIS_LIB_DIR=.*#CIS_LIB_DIR='$(pwd)'/lib#" /etc/default/cis-hardening
sed -i "s#CIS_CHECKS_DIR=.*#CIS_CHECKS_DIR='$(pwd)'/bin/hardening#" /etc/default/cis-hardening
sed -i "s#CIS_CONF_DIR=.*#CIS_CONF_DIR='$(pwd)'/etc#" /etc/default/cis-hardening
sed -i "s#CIS_TMP_DIR=.*#CIS_TMP_DIR='$(pwd)'/tmp#" /etc/default/cis-hardening
sed -i "s#CIS_VERSIONS_DIR=.*#CIS_VERSIONS_DIR='$(pwd)'/versions#" /etc/default/cis-hardening
bin/hardening.sh --audit-all --allow-unsupported-distribution
bin/hardening.sh --set-hardening-level 5 --allow-unsupported-distribution
rm /home/dev/debian-cis/bin/hardening/disable_print_server.sh
rm /home/dev/debian-cis/bin/hardening/disable_avahi_server.sh
rm /home/dev/debian-cis/bin/hardening/disable_xwindow_system.sh
rm /home/dev/debian-cis/bin/hardening/install_tripwire.sh
bin/hardening.sh --apply --allow-unsupported-distribution
bin/hardening.sh --apply --allow-unsupported-distribution
bin/hardening.sh --apply --allow-unsupported-distribution

cat >/etc/sudoers <<'EOF'
Defaults passwd_tries=2
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
root   ALL=(ALL) ALL
%sudo  ALL=(ALL) ALL
EOF

# MISC HARDENING 
echo "/bin/bash" > /etc/shells
passwd -l root
echo "needs_root_rights=no" >> /etc/X11/Xwrapper.config
dpkg-reconfigure xserver-xorg-legacy
echo "order hosts" >> /etc/host.conf

sed -i 's/^# End of file*//' /etc/security/limits.conf
 { echo '*     hard  maxlogins 1'
   echo '*     hard  core 0'
   echo '*     soft  core 0'
  } >> /etc/security/limits.conf
echo "ProcessSizeMax=0
Storage=none" >> /etc/systemd/coredump.conf
echo "ulimit -c 0" >> /etc/profile

sed -i 's/^UMASK.*/UMASK 077/' /etc/login.defs
echo "umask 077" >> /etc/profile
echo "umask 077" >> /etc/bash.bashrc
echo "ALL: LOCAL, 127.0.0.1" >> /etc/hosts.allow
echo "ALL: ALL" > /etc/hosts.deny
chmod 644 /etc/hosts.allow
chmod 644 /etc/hosts.deny
 
# GRUB
sed -i 's|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT="slab_nomerge init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 pti=on vsyscall=none debugfs=off oops=panic module.sig_enforce=1 lockdown=confidentiality mce=0 quiet loglevel=0 spectre_v2=on spec_store_bypass_disable=on tsx=off tsx_async_abort=full,nosmt mds=full,nosmt l1tf=full,force nosmt=force kvm.nx_huge_pages=force ipv6.disable=1 apparmor=1 security=apparmor"|' /etc/default/grub
update-grub
chown root:root /etc/default/grub
chmod 640 /etc/default/grub 
chattr +i /etc/default/grub

# MESSAGE
echo "
Unauthorized access to this server is prohibited.
All connections are monitored and recorded.
Legal action will be taken. Please disconnect now.
" >> /etc/motd  
  
echo "
Unauthorized access to this server is prohibited.
All connections are monitored and recorded.
Legal action will be taken. Please disconnect now.
" >> /etc/issue
  
echo "
Unauthorized access to this server is prohibited.
All connections are monitored and recorded.
Legal action will be taken. Please disconnect now.
" >> /etc/issue.net

# MODULES
cat > /etc/modprobe.d/harden.conf << 'EOF'
blacklist kvm
install kvm /bin/false
blacklist kvm_intel
install kvm_intel /bin/false
blacklist kvm_amd
install kvm_amd /bin/false
blacklist vboxdrv
install vboxdrv /bin/false
blacklist vboxnetflt
install vboxnetflt /bin/false
blacklist vboxnetadp
install vboxnetadp /bin/false
blacklist vmw_vmci
install vmw_vmci /bin/false
blacklist vmmon
install vmmon /bin/false
blacklist xen
install xen /bin/false
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
install n-hdlc /bin/false
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
install cifs /bin/true
install nfs /bin/true
install nfsv3 /bin/true
install nfsv4 /bin/true
install ksmbd /bin/true
install gfs2 /bin/true
install vivid /bin/false
install bluetooth /bin/false
install btusb /bin/false
install uvcvideo /bin/false
EOF

# KERNEL
rm -r /etc/sysctl.d
rm -r /usr/lib/sysctl.d
echo "kernel.kptr_restrict=2
kernel.dmesg_restrict=1
kernel.printk=3 3 3 3
kernel.unprivileged_bpf_disabled=1
net.core.bpf_jit_harden=2
dev.tty.ldisc_autoload=0
vm.unprivileged_userfaultfd=0
kernel.kexec_load_disabled=1
kernel.sysrq=4
kernel.unprivileged_userns_clone=0
kernel.perf_event_paranoid=3
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_rfc1337=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.icmp_echo_ignore_all=1
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv6.conf.all.accept_source_route=0
net.ipv6.conf.default.accept_source_route=0
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0
net.ipv4.tcp_sack=0
net.ipv4.tcp_dsack=0
net.ipv4.tcp_fack=0
net.ipv4.tcp_timestamps=0
kernel.yama.ptrace_scope=2
vm.mmap_rnd_bits=32
vm.mmap_rnd_compat_bits=16
fs.protected_symlinks=1
fs.protected_hardlinks=1
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
" > /etc/sysctl.conf
sysctl --system

# MOUNTS
echo "
proc                                      /proc                      proc       nosuid,nodev,noexec,hidepid=2 0 0
" >> /etc/fstab

# LOCKDOWN
chmod o-rx /usr/bin/as
chattr +i /etc/fstab
chattr +i /etc/adduser.conf
chattr +i /etc/group
chattr +i /etc/group-
chattr +i /etc/hosts
chattr +i /etc/host.conf
chattr +i /etc/hosts.allow
chattr +i /etc/hosts.deny
chattr +i /etc/login.defs
chattr -R +i /etc/default
chattr +i /etc/passwd
chattr +i /etc/passwd-
chattr +i /etc/securetty
chattr -R +i /etc/security
chattr +i /etc/gshadow-
chattr +i /etc/gshadow
chattr -R +i /etc/ssh
chattr -R +i /etc/sudoers.d
chattr +i /root/.bashrc
chattr +i /etc/shadow
chattr +i /etc/shadow-
chattr +i /etc/shells
chattr -R +i /etc/pam.d
chattr +i /etc/sysctl.conf
chattr -R +i /etc/modprobe.d
chattr +i /etc/services
chattr +i /etc/sudoers
