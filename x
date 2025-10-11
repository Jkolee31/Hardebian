#!/usr/bin/env bash

set -euo pipefail

# PRE CONFIG/AUDIT
echo 'APT::Install-Recommends "false";' >> /etc/apt/apt.conf.d/98-hardening 
apt update

git clone https://github.com/ovh/debian-cis.git && cd debian-cis
cp debian/default /etc/default/cis-hardening
sed -i "s#CIS_LIB_DIR=.*#CIS_LIB_DIR='$(pwd)'/lib#" /etc/default/cis-hardening
sed -i "s#CIS_CHECKS_DIR=.*#CIS_CHECKS_DIR='$(pwd)'/bin/hardening#" /etc/default/cis-hardening
sed -i "s#CIS_CONF_DIR=.*#CIS_CONF_DIR='$(pwd)'/etc#" /etc/default/cis-hardening
sed -i "s#CIS_TMP_DIR=.*#CIS_TMP_DIR='$(pwd)'/tmp#" /etc/default/cis-hardening
sed -i "s#CIS_VERSIONS_DIR=.*#CIS_VERSIONS_DIR='$(pwd)'/versions#" /etc/default/cis-hardening
bin/hardening.sh --audit-all --allow-unsupported-distribution
bin/hardening.sh --set-hardening-level 5 --allow-unsupported-distribution
bin/hardening.sh --apply --allow-unsupported-distribution
bin/hardening.sh --apply --allow-unsupported-distribution
bin/hardening.sh --apply --allow-unsupported-distribution

apt purge iptables ufw virtualbox* lxc* docker* podman* xen* bochs* uml-utilities vagrant* ssh* openssh* acpi* anacron* samba winbind qemu-system* qemu-utils libvirt* virt-manager cron* avahi* cup* zram* print* rsync* virtual* sane* rpc* bind* nfs* blue* pp* mesa* spee* espeak* mobile* wireless* bc perl blue* inet* python3 apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra dictionaries-common doc-debian emacsen-common ethtool iamerican ibritish ienglish-common inetutils-telnet ispell task-english util-linux-locales wamerican wtmpdb zerofree tasksel tasksel-data vim-tiny vim-common

install -d /etc/apt/preferences.d
cat >/etc/apt/preferences.d/deny-ssh.pref <<'EOF'
Package: openssh*
Pin: release *
Pin-Priority: -1

Package: dropbear
Pin: release *
Pin-Priority: -1

Package: ssh*
Pin: release *
Pin-Priority: -1

Package: libssh*
Pin: release *
Pin-Priority: -1

Package: tinyssh
Pin: release *
Pin-Priority: -1

Package: qemu*       
Pin: release *
Pin-Priority: -1

Package: libvirt*
Pin: release *
Pin-Priority: -1

Package: virtualbox*
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

Package: vagrant*
Pin: release *
Pin-Priority: -1

Package: systemd*
Pin: release *
Pin-Priority: -1

Package: libsystemd0
Pin: release *
Pin-Priority: -1

Package: libpam-systemd
Pin: release *
Pin-Priority: -1

Package: systemd-sysv
Pin: release *
Pin-Priority: -1

Package: systemd-container
Pin: release *
Pin-Priority: -1

Package: systemd-timesyncd
Pin: release *
Pin-Priority: -1

EOF
apt update

  cat >/etc/sudoers <<'EOF'
Defaults passwd_tries=2
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
root    ALL=(ALL) ALL
%wheel  ALL=(ALL) ALL
EOF


apt install -y  pamu2fcfg libpam-u2f apparmor rsyslog chrony apparmor-utils apparmor-profiles apparmor-profiles-extra apt-listbugs apt-listchanges needrestart debsecan debsums acct wget gnupg lsb-release apt-transport-https unzip patch pulseaudio pulseaudio-utils pavucontrol alsa-utils rkhunter chkrootkit lynis macchanger unhide tcpd haveged lsb-release apt-transport-https auditd fonts-liberation extrepo gnome-terminal gnome-brave-icon-theme breeze-gtk-theme bibata* tcpd macchanger mousepad libxfce4ui-utils thunar xfce4-panel xfce4-session xfce4-settings xfce4-terminal xfconf xfdesktop4 xfwm4 xserver-xorg xinit xserver-xorg-legacy xfce4-pulse* xfce4-whisk* lightdm lightdm-gtk-greeter lightdm-gtk-greeter-settings opensnitch* python3-opensnitch*

#U2F
mkdir /home/dev/.config
pamu2fcfg > /home/dev/.config/default
sed -i 's/.*:/dev:/' /home/dev/.config/default
chmod 600 /home/dev/.config/default
install -o root -g root -m 600 /home/dev/.config/default /etc/conf
addgroup wheel
install -d /etc/sudoers.d
echo "%wheel  ALL=(ALL) ALL" >/etc/sudoers.d/00wheel
chmod 440 /etc/sudoers.d/00wheel
adduser dev wheel

cat >/etc/pam.d/common-auth <<'EOF'
#%PAM-1.0
auth      sufficient pam_u2f.so authfile=/etc/conf
auth      [success=1 default=ignore] pam_unix.so try_first_pass
auth      requisite  pam_deny.so
auth      required   pam_permit.so
EOF
cat >/etc/pam.d/common-account <<'EOF'
#%PAM-1.0
account   required   pam_unix.so
EOF
cat >/etc/pam.d/common-session <<'EOF'
#%PAM-1.0
session   required   pam_limits.so
session   required   pam_env.so
session   optional   pam_systemd.so
session   required   pam_unix.so
EOF
cat >/etc/pam.d/common-session-noninteractive <<'EOF'
#%PAM-1.0
session   required   pam_limits.so
session   required   pam_env.so
session   optional   pam_systemd.so
session   required   pam_unix.so
EOF
cat >/etc/pam.d/common-password <<'EOF'
#%PAM-1.0
password  [success=1 default=ignore] pam_unix.so obscure use_authtok try_first_pass yescrypt
password  requisite  pam_deny.so
password  required   pam_permit.so
EOF
cat >/etc/pam.d/sudo <<'EOF'
#%PAM-1.0
auth      required   pam_u2f.so authfile=/etc/conf
account   required   pam_unix.so
password  required   pam_unix.so
session   required   pam_limits.so
session   required   pam_env.so
session   required   pam_unix.so
EOF
cat >/etc/pam.d/sudo-i <<'EOF'
#%PAM-1.0
auth      required   pam_u2f.so authfile=/etc/conf
account   required   pam_unix.so
password  required   pam_unix.so
session   required   pam_limits.so
session   required   pam_env.so
session   required   pam_unix.so
EOF
cat >/etc/pam.d/sshd <<'EOF'
#%PAM-1.0
auth      required   pam_u2f.so authfile=/etc/conf
account   required   pam_unix.so
password  required   pam_unix.so
session   required   pam_limits.so
session   required   pam_env.so
session   required   pam_unix.so
EOF
cat >/etc/pam.d/su <<'EOF'
#%PAM-1.0
auth      required   pam_u2f.so authfile=/etc/conf
account   required   pam_unix.so
password  required   pam_unix.so
session   required   pam_limits.so
session   required   pam_env.so
session   required   pam_unix.so
EOF
cat >/etc/pam.d/su-l <<'EOF'
#%PAM-1.0
auth      required   pam_u2f.so authfile=/etc/conf
account   required   pam_unix.so
password  required   pam_unix.so
session   required   pam_limits.so
session   required   pam_env.so
session   required   pam_unix.so
EOF
cat >/etc/pam.d/other <<'EOF'
#%PAM-1.0
auth      required   pam_deny.so
account   required   pam_deny.so
password  required   pam_deny.so
session   required   pam_deny.so
EOF
cat >/etc/pam.d/login <<'EOF'
#%PAM-1.0
auth      requisite  pam_securetty.so
auth      include    common-auth
account   include    common-account
password  include    common-password
session   required   pam_limits.so
session   required   pam_unix.so
EOF

chattr +i -R /etc/pam.d/*

# FIREWALL
cat >/etc/nftables.conf <<EOF
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

# MISC HARDENING 
touch /etc/securetty
chown  root:root /etc/securetty
chmod  400 /etc/securetty
echo "console" >  etc/securetty
echo "/bin/bash" > /etc/shells
passwd -l root
echo "needs_root_rights=no" >> /etc/X11/Xwrapper.config
dpkg-reconfigure xserver-xorg-legacy
echo "order hosts" >> /etc/host.conf

sed -i 's/^# End of file*//' /etc/security/limits.conf
 { echo '*     hard  maxlogins 2'
   echo 'root  hard  maxlogins 10'
   echo '*     hard  core 0'
   echo '*     hard  nproc 100'  
   echo '# End of file'
  } >> /etc/security/limits.conf
echo "ProcessSizeMax=0
Storage=none" >> /etc/systemd/coredump.conf
echo "ulimit -c 0" >> /etc/profile

sed -i 's/^DIR_MODE=.*/DIR_MODE=0750/' -e 's/^#DIR_MODE=.*/DIR_MODE=0750/' /etc/adduser.conf
sed -i 's/^DSHELL=.*/DSHELL=\/usr\/sbin\/nologin/' -e 's/^#DSHELL=.*/DSHELL=\/usr\/sbin\/nologin/' /etc/adduser.conf
sed -i 's/^USERGROUPS=.*/USERGROUPS=yes/' -e 's/^#USERGROUPS=.*/USERGROUPS=yes/' /etc/adduser.conf
sed -i 's/^SHELL=.*/SHELL=\/bin\/false/' /etc/default/useradd 
sed -i 's/^# INACTIVE=.*/INACTIVE=30/' /etc/default/useradd
sed -i 's/^.*LOG_OK_LOGINS.*/LOG_OK_LOGINS yes/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 60/' /etc/login.defs
sed -i 's/DEFAULT_HOME.*/DEFAULT_HOME no/' /etc/login.defs
sed -i 's/ENCRYPT_METHOD.*/ENCRYPT_METHOD YESCRYPT/' /etc/login.defs
sed -i 's/USERGROUPS_ENAB.*/USERGROUPS_ENAB no/' /etc/login.defs
sed -i 's/umask 077/umask 027/g' /etc/init.d/rc
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
blacklist dccp
install dccp /bin/false
blacklist sctp
install sctp /bin/false
blacklist rds
install rds /bin/false
blacklist tipc
install tipc /bin/false
blacklist ax25
install ax25 /bin/false
blacklist netrom
install netrom /bin/false
blacklist x25
install x25 /bin/false
blacklist rose
install rose /bin/false
blacklist decnet
install decnet /bin/false
blacklist econet
install econet /bin/false
blacklist af_802154
install af_802154 /bin/false
blacklist ipx
install ipx /bin/false
blacklist appletalk
install appletalk /bin/false
blacklist psnap
install psnap /bin/false
blacklist p8023
install p8023 /bin/false
blacklist p8022
install p8022 /bin/false
blacklist can
install can /bin/false
blacklist atm
install atm /bin/false
blacklist cramfs
install cramfs /bin/false
blacklist freevxfs
install freevxfs /bin/false
blacklist jffs2
install jffs2 /bin/false
blacklist hfs
install hfs /bin/false
blacklist hfsplus
install hfsplus /bin/false
blacklist squashfs
install squashfs /bin/false
blacklist udf
install udf /bin/false
blacklist cifs
install cifs /bin/false
blacklist nfs
install nfs /bin/false
blacklist nfsd 
install nfsd /bin/false
blacklist nfsv3
install nfsv3 /bin/false
blacklist nfsv4
install nfsv4 /bin/false
blacklist lockd
install lockd /bin/false
blacklist ksmbd
install ksmbd /bin/false
blacklist gfs2
install gfs2 /bin/false
blacklist bluetooth
install bluetooth /bin/false
blacklist btusb
install btusb /bin/false
blacklist firewire-core
install firewire-core /bin/false
blacklist thunderbolt
install thunderbolt /bin/false
blacklist usb-storage
install usb-storage /bin/false
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
securityfs                                /sys/kernel/security       securityfs nosuid,nodev,noexec 0 0
pstore                                    /sys/fs/pstore             pstore     nosuid,nodev,noexec 0 0
systemd                                   /sys/fs/cgroup/systemd     cgroup     nosuid,nodev,noexec 0 0
cgroup                                    /sys/fs/cgroup             tmpfs      nosuid,nodev,noexec 0 0
efivarfs                                  /sys/firmware/efi/efivars  efivarfs   nosuid,nodev,noexec 0 0
net_cls                                   /sys/fs/cgroup/net_cls     cgroup     nosuid,nodev,noexec 0 0
tmpfs                                     /home/dev/.cache           tmpfs      nosuid,nodev,noexec,uid=1000,gid=1000,mode=700 0 0
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
chattr -R +i /etc/modprobe.d
chattr +i /etc/services
chattr +i /etc/sudoers
