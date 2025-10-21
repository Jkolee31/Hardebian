#!/usr/bin/env bash

set -euo pipefail

mount /usr -o remount,rw /usr
mount /usr -o remount,rw /boot

apt update
apt purge -y  iptables* ufw gufw zram* yad* xfce4-wavelan-plugin xfce4-places-plugin xfce4-mount-plugin xfce4-genmon-plugin xfce4-fsguard-plugin xfce4-docklike-plugin xfce-superkey-mx pci* papirus* orca* nfs* network-manager* mx-usb-unmounter mx-goodies pmount* libspa-0.2-bluetooth libspa-0.2-libcamera libpocketsphinx3  libjansson4 acpi* anacron* cron* avahi* atmel* bc bind9* ddm-mx dns* fastfetch fonts-noto* fprint* isc-dhcp* iptables* ufw lxc* docker* podman* xen* bochs* uml* vagrant* libssh* ssh* openssh* acpi* samba* winbind* qemu* libvirt* virt* cron* avahi* cup* zram* print* rsync* virtual* sane* rpc* bind* nfs* blue* pp* spee* espeak* mobile* wireless* bc perl blue* dictionaries-common doc-debian emacs* ethtool iamerican ibritish ienglish-common inet* ispell task-english util-linux-locales wamerican tasksel* vim*

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

Package: cron*
Pin: release *
Pin-Priority: -1

Package: anacron*
Pin: release *
Pin-Priority: -1

Package: exim*
Pin: release *
Pin-Priority: -1

Package: syslog*
Pin: release *
Pin-Priority: -1

Package: rsync*
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

Package: mobile*
Pin: release *
Pin-Priority: -1

Package: wireless*
Pin: release *
Pin-Priority: -1

Package: perl*
Pin: release *
Pin-Priority: -1

Package: inet*
Pin: release *
Pin-Priority: -1

Package: vagrant*
Pin: release *
Pin-Priority: -1

Package: systemd*
Pin: release *
Pin-Priority: -1

Package: libsystemd*
Pin: release *
Pin-Priority: -1

Package: libpam-systemd*
Pin: release *
Pin-Priority: -1
EOF

apt update 

apt install -y nftables pamu2fcfg libpam-u2f

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
password  optional    pam_gnome_keyring.so 
EOF

cat >/etc/pam.d/common-auth <<'EOF'
#%PAM-1.0
auth      sufficient  pam_u2f.so authfile=/etc/conf
auth      requisite   pam_faillock.so preauth
auth      [success=2  default=ignore]  pam_unix.so try_first_pass
auth      [default=die] pam_faillock.so authfail
auth      requisite   pam_deny.so
auth      required    pam_permit.so
EOF

cat >/etc/pam.d/common-session <<'EOF'
#%PAM-1.0
session   required    pam_limits.so
session   required    pam_env.so
session   optional    pam_elogind.so
session   required    pam_unix.so
EOF

cat >/etc/pam.d/common-session-noninteractive <<'EOF'
#%PAM-1.0
session   required    pam_limits.so
session   required    pam_env.so
session   optional    pam_elogind.so
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

cat >/etc/pam.d/elogind-user <<'EOF'
#%PAM-1.0
account   include     common-account
session   required    pam_selinux.so close
session   required    pam_selinux.so nottys open
session   required    pam_loginuid.so
session   required    pam_limits.so
session   include     common-session-noninteractive
session   optional    pam_elogind.so
EOF

cat >/etc/pam.d/lightdm <<'EOF'
#%PAM-1.0
auth      requisite   pam_nologin.so
session   required    pam_env.so readenv=1
session   required    pam_env.so readenv=1 envfile=/etc/default/locale
auth      include     common-auth
auth      optional    pam_gnome_keyring.so
account   include     common-account
session   [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so close
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
session   optional    pam_systemd.so
session   required    pam_env.so readenv=1
session   required    pam_env.so readenv=1 envfile=/etc/default/locale
session   include     common-session
EOF

cat >/etc/pam.d/login <<'EOF'
#%PAM-1.0
auth      optional    pam_faildelay.so  delay=3000000
auth      requisite   pam_nologin.so
session   [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so close
session   required    pam_loginuid.so
session   [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so open
session   required    pam_env.so readenv=1
session   required    pam_env.so readenv=1 envfile=/etc/default/locale
auth      include     common-auth
account   required    pam_access.so
session   required    pam_limits.so
session   optional    pam_keyinit.so force revoke
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
auth	    sufficient  pam_rootok.so
session	  optional    pam_keyinit.so revoke
session	  required    pam_limits.so
session	  required    pam_unix.so
EOF

cat >/etc/pam.d/runuser-l <<'EOF'
#%PAM-1.0
auth	  include     runuser
session	  optional    pam_keyinit.so force revoke
-session  optional    pam_systemd.so
session	  include     runuser
EOF

chattr +i -R /etc/pam.d/*

# FIREWALL
cat >/etc/nftables.conf <<'EOF'
flush ruleset

table inet filter {
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

nft -f /etc/nftables.conf
chattr +i /etc/nftables.conf

# PRE CONFIG/AUDIT
echo 'APT::Get::AllowUnauthenticated "false";' >> /etc/apt/apt.conf.d/98-hardening
echo 'APT::Install-Suggests "false";' >> /etc/apt/apt.conf.d/98-hardening 
echo 'APT::Install-Recommends "false";' >> /etc/apt/apt.conf.d/98-hardening 
echo 'DPkg
  {
      Pre-Invoke  { "mount /usr -o remount,rw" };
  };' >> /etc/apt/apt.conf.d/99-remount

apt update

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
bin/hardening.sh --apply --allow-unsupported-distribution
bin/hardening.sh --apply --allow-unsupported-distribution
bin/hardening.sh --apply --allow-unsupported-distribution

cat >/etc/sudoers <<'EOF'
Defaults passwd_tries=2
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
dev  ALL=(ALL) ALL
EOF

cat >/etc/sudoers.d/antixers <<'EOF'
dev ALL=(root) NOPASSWD: /sbin/poweroff
dev ALL=(root) NOPASSWD: /sbin/reboot  
dev ALL=(root) NOPASSWD: /usr/bin/apt update -y
dev ALL=(root) NOPASSWD: /usr/bin/apt upgrade -y
dev ALL=(root) NOPASSWD: /usr/sbin/nft list *
EOF

#FINAL INSTALL (NEW AND/OR INCASE ANYTHING WAS DELETED)
apt install -y  nftables pamu2fcfg libpam-u2f rsyslog chrony debsecan debsums acct wget gnupg lsb-release apt-transport-https unzip lynis macchanger unhide tcpd haveged lsb-release apt-transport-https auditd fonts-liberation extrepo gnome-terminal gnome-brave-icon-theme breeze-gtk-theme bibata* tcpd macchanger mousepad libxfce4ui-utils thunar xfce4-panel xfce4-session xfce4-settings xfce4-terminal xfconf xfdesktop4 xfwm4 xserver-xorg xinit xserver-xorg-legacy xfce4-pulse* xfce4-whisk* opensnitch* python3-opensnitch*


# MISC HARDENING 
echo "/bin/bash" > /etc/shells
passwd -l root
echo "needs_root_rights=no" >> /etc/X11/Xwrapper.config
dpkg-reconfigure xserver-xorg-legacy
echo "order hosts" >> /etc/host.conf

sed -i 's/^# End of file*//' /etc/security/limits.d/limits.conf
 { echo '*     hard  maxlogins 2'
   echo '*     hard  core 0'
   echo '*     soft  core 0'
   echo '*     hard  nproc 200'
   echo '*     soft  nproc 200'
  } >> /etc/security/limits.d/limits.conf
echo "ProcessSizeMax=0
Storage=none" >> /etc/systemd/coredump.conf
echo "ulimit -c 0" >> /etc/profile

sed -i -e 's/^DSHELL=.*/DSHELL=\/usr\/sbin\/nologin/'  /etc/adduser.conf
sed -i 's/^SHELL=.*/SHELL=\/usr\/sbin\/nologin/' /etc/default/useradd
sed -i 's/ENCRYPT_METHOD.*/ENCRYPT_METHOD YESCRYPT/' /etc/login.defs
sed -i 's/^UMASK.*/UMASK 077/' /etc/login.defs
sed -i 's/umask.*/umask 077/g' /etc/init.d/rc
echo "umask 077" >> /etc/profile
echo "umask 077" >> /etc/bash.bashrc
echo "ALL: LOCAL, 127.0.0.1" >> /etc/hosts.allow
echo "ALL: ALL" > /etc/hosts.deny
chmod 644 /etc/hosts.allow
chmod 644 /etc/hosts.deny
 
# GRUB
sed -i 's|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT="slab_nomerge slub_debug=FZ init_on_alloc=1 init_on_free=1 page_alloc.shuffle=1 pti=on vsyscall=none debugfs=off oops=panic module.sig_enforce=1 lockdown=confidentiality mce=0 quiet loglevel=0 ipv6.disable=1 spectre_v2=on spec_store_bypass_disable=on tsx=off tsx_async_abort=full,nosmt mds=full,nosmt l1tf=full,force nosmt=force kvm.nx_huge_pages=force quiet loglevel=0 apparmor=1 security=apparmor"|' /etc/default/grub
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
EOF

# KERNEL
rm -r /etc/sysctl.d
rm -r /usr/lib/sysctl.d
echo "dev.tty.ldisc_autoload=0
fs.protected_fifos = 2
fs.protected_hardlinks = 1
fs.protected_regular = 2
fs.protected_symlinks = 1
fs.suid_dumpable = 0
kernel.dmesg_restrict = 1
kernel.kexec_load_disabled = 1
kernel.kptr_restrict = 2
kernel.randomize_va_space = 2
kernel.unprivileged_bpf_disabled = 1
kernel.yama.ptrace_scope = 3
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.ip_forward = 0
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
vm.mmap_rnd_bits=32
vm.mmap_rnd_compat_bits=16" > /etc/sysctl.conf
sysctl --system

# MOUNTS
echo "
proc                                      /proc                      proc       nosuid,nodev,noexec,hidepid=2 0 0
tmpfs                                     /tmp                       tmpfs      nosuid,nodev,noexec,mode=1777 0 0
tmpfs                                     /var/tmp                   tmpfs      nosuid,nodev,noexec,mode=1777 0 0
" >> /etc/fstab

# LOCKDOWN
find / -perm -4000 -o -perm -2000 -exec chmod a-s {} \; 2>/dev/null
find / -perm -4000 -exec chmod u-s {} \;
find / -perm -4000 -exec chmod g-s {} \;
find / -perm -2000 -exec chmod u-s {} \;
find / -perm -2000 -exec chmod g-s {} \;
chmod u+s /usr/bin/sudo
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

mount /usr -o remount,ro /boot
mount /usr -o remount,ro /usr
chattr -R +i /etc/modprobe.d
chattr +i /etc/services
chattr +i /etc/sudoers
