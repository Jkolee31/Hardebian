#!/usr/bin/env bash

set -euo pipefail

# PRE CONFIG
cat >/etc/apt/apt.conf.d/98-hardening <<'EOF'
APT::Get::AllowUnauthenticated "false";
Acquire::http::AllowRedirect "false";
APT::Install-Recommends "false";
EOF
apt update

# FIREWALL
apt install -y iptables iptables-persistent netfilter-persistent
systemctl enable netfilter-persistent
service netfilter-persistent start
iptables -F
iptables -X
iptables -Z
iptables -t nat -F
iptables -t nat -X
iptables -t nat -Z
iptables -t mangle -F
iptables -t mangle -X
iptables -t mangle -Z
iptables -N UDP
iptables -N TCP
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -p udp -m conntrack --ctstate NEW -j UDP
iptables -A INPUT -p tcp --syn -m conntrack --ctstate NEW -j TCP
iptables -A INPUT -p udp -j DROP
iptables -A INPUT -p tcp -j DROP
iptables -A INPUT -j DROP
iptables -A UDP -p udp --dport 53 -j ACCEPT
iptables -A TCP -p tcp --dport 443 -j ACCEPT
iptables -A TCP -p tcp --dport 80 -j ACCEPT
ip6tables -F
ip6tables -X
ip6tables -Z
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT DROP
iptables-save   > /etc/iptables/rules.v4
ip6tables-save  > /etc/iptables/rules.v6
netfilter-persistent save

# PACKAGE RESTRICTIONS
apt purge -y  zram* pci* pmount* acpi* anacron* avahi* bc bind9* dns* fastfetch fonts-noto* fprint* isc-dhcp* lxc* docker* podman* xen* bochs* uml* vagrant* libssh* ssh* openssh* acpi* samba* winbind* qemu* libvirt* virt* cron* avahi* cup* print* rsync* nftables* virtual* sane* rpc* bind* nfs* blue* pp* spee* espeak* mobile* wireless* bc perl inet* util-linux-locales tasksel* vim* os-prober* netcat* libssh* gcc g++ gdb lldb strace* ltrace* build-essential automake autoconf libtool cmake ninja-build meson

install -d /etc/apt/preferences.d
cat >/etc/apt/preferences.d/deny.pref <<'EOF'
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

Package: courier*
Pin: release *
Pin-Priority: -1

Package: dma*
Pin: release *
Pin-Priority: -1

Package: tripwire*
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

Package: netcat*
Pin: release *
Pin-Priority: -1

Package: os-prober*
Pin: release *
Pin-Priority: -1

Package: make*
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

Package: nftables*
Pin: release *
Pin-Priority: -1

Package: gcc*
Pin: release *
Pin-Priority: -1

Package: g++*
Pin: release *
Pin-Priority: -1

Package: gdb*
Pin: release *
Pin-Priority: -1

Package: lldb*
Pin: release *
Pin-Priority: -1

Package: strace*
Pin: release *
Pin-Priority: -1

Package: ltrace*
Pin: release *
Pin-Priority: -1

Package: build-essential*
Pin: release *
Pin-Priority: -1

Package: automake*
Pin: release *
Pin-Priority: -1

Package: autoconf*
Pin: release *
Pin-Priority: -1

Package: cmake*
Pin: release *
Pin-Priority: -1

Package: nasm*
Pin: release *
Pin-Priority: -1

Package: yasm*
Pin: release *
Pin-Priority: -1
EOF

# INSTALL PACKAGES
apt install -y apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra pamu2fcfg libpam-u2f rsyslog chrony libpam-tmpdir fail2ban needrestart apt-listchanges acct sysstat rkhunter chkrootkit debsums apt-show-versions unzip patch alsa-utils pavucontrol pipewire pipewire-audio-client-libraries pipewire-pulse wireplumber lynis macchanger unhide tcpd fonts-liberation extrepo gnome-brave-icon-theme breeze-gtk-theme bibata* mousepad libxfce4ui-utils thunar xfce4-panel xfce4-session xfce4-settings xfce4-terminal xfconf xfdesktop4 xfwm4 xserver-xorg xinit xserver-xorg-legacy xfce4-pulse* xfce4-whisk* opensnitch* python3-opensnitch*
systemctl enable apparmor
systemctl start apparmor
aa-enforce /etc/apparmor.d/* 2>/dev/null || true

# OPENSNITCH CONFIGURATION
systemctl enable opensnitch
systemctl start opensnitch
apt install -y git
git clone --depth 1 https://github.com/DXC-0/Respect-My-Internet.git
cd Respect-My-Internet
chmod +x install.sh
./install.sh
systemctl restart opensnitch

# PAM/U2F
pamu2fcfg -u dev > /etc/conf
chmod 600 /etc/conf
chown root:root /etc/conf

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
account   required    pam_unix.so
EOF

cat >/etc/pam.d/common-password <<'EOF'
#%PAM-1.0
password  [success=1  default=ignore]  pam_unix.so obscure use_authtok try_first_pass yescrypt
password  requisite   pam_deny.so
EOF

cat >/etc/pam.d/common-auth <<'EOF'
#%PAM-1.0
auth      sufficient  pam_u2f.so authfile=/etc/conf
auth      requisite   pam_deny.so
EOF

cat >/etc/pam.d/common-session <<'EOF'
#%PAM-1.0
session   required    pam_limits.so
session   required    pam_env.so
session   optional    pam_systemd.so
session   optional    pam_umask.so umask=077
session   optional    pam_tmpdir.so
session   required    pam_unix.so
EOF

cat >/etc/pam.d/common-session-noninteractive <<'EOF'
#%PAM-1.0
session   required    pam_limits.so
session   required    pam_env.so
session   optional    pam_systemd.so
session   optional    pam_umask.so umask=077
session   optional    pam_tmpdir.so
session   required    pam_unix.so
EOF

cat >/etc/pam.d/sudo <<'EOF'
#%PAM-1.0
auth      required    pam_u2f.so authfile=/etc/conf
account   include     common-account
password  include     common-password
session   include     common-session
EOF

cat >/etc/pam.d/sudo-i <<'EOF'
#%PAM-1.0
auth      required    pam_u2f.so authfile=/etc/conf
account   include     common-account
password  include     common-password
session   include     common-session
EOF

cat >/etc/pam.d/sshd <<'EOF'
#%PAM-1.0
auth      required    pam_u2f.so authfile=/etc/conf
account   include     common-account
password  include     common-password
session   include     common-session
EOF

cat >/etc/pam.d/su <<'EOF'
#%PAM-1.0
auth      required    pam_u2f.so authfile=/etc/conf
account   include     common-account
password  include     common-password
session   include     common-session
EOF

cat >/etc/pam.d/su-l <<'EOF'
#%PAM-1.0
auth      required    pam_u2f.so authfile=/etc/conf
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

cat >/etc/pam.d/login <<'EOF'
#%PAM-1.0
auth      optional    pam_faildelay.so delay=3000000
auth      requisite   pam_nologin.so
auth      required    pam_u2f.so authfile=/etc/conf
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
auth	  sufficient  pam_rootok.so
session	  required    pam_limits.so
session	  required    pam_unix.so
EOF

cat >/etc/pam.d/runuser-l <<'EOF'
#%PAM-1.0
auth	  include     runuser
session	  include     runuser
EOF

# SUDO
cat >/etc/sudoers <<'EOF'
Defaults passwd_tries=2
Defaults use_pty
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
root  ALL=(ALL) ALL
%sudo ALL=(ALL) ALL
EOF
chmod 0440 /etc/sudoers
chmod 0440 /etc/sudoers.d

# MISC HARDENING
echo "/bin/bash" > /etc/shells
passwd -l root
echo "needs_root_rights=no" >> /etc/X11/Xwrapper.config
dpkg-reconfigure xserver-xorg-legacy

cat >/etc/host.conf <<'EOF'
multi on
order hosts,bind
EOF

cat >/etc/security/limits.d/limits.conf <<'EOF'
*     hard  core       0
*     hard  nproc      200
*     hard  nofile     1024
*     soft  nofile     512
*     -     maxlogins  1
root  -     maxlogins  5
root  hard  nproc      3000
EOF

echo "ProcessSizeMax=0
Storage=none" >> /etc/systemd/coredump.conf
echo "ulimit -c 0" >> /etc/profile

sed -i 's/^#\?REMOVE_HOME.*/REMOVE_HOME = yes/' /etc/deluser.conf
sed -i 's/^#\?REMOVE_ALL_FILES.*/REMOVE_ALL_FILES = yes/' /etc/deluser.conf
sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 10/' /etc/login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 10/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs
sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD YESCRYPT/' /etc/login.defs
sed -i 's/^UID_MIN.*/UID_MIN 1000/' /etc/login.defs
sed -i 's/^UID_MAX.*/UID_MAX 60000/' /etc/login.defs
sed -i 's/^CREATE_HOME.*/CREATE_HOME yes/' /etc/login.defs
sed -i 's/^CHFN_RESTRICT.*/CHFN_RESTRICT /' /etc/login.defs
sed -i "/^SHELL=/ s/=.*\+/=\/usr\/sbin\/nologin/" /etc/default/useradd
sed -i "/^DSHELL=/ s/=.*\+/=\/usr\/sbin\/nologin/" /etc/adduser.conf
echo "UMASK 077" >> /etc/login.defs
echo "umask 077" >> /etc/profile
echo "umask 077" >> /etc/bash.bashrc
echo "ALL: LOCAL, 127.0.0.1" >> /etc/hosts.allow
echo "ALL: ALL" > /etc/hosts.deny

cat > /etc/security/access.conf << 'EOF'
-:ALL EXCEPT dev:tty1
-:ALL EXCEPT dev:LOCAL
-:dev:ALL EXCEPT LOCAL
+:dev:tty1 tty2 tty3 tty4 tty5 tty6
-:root:ALL
-:ALL:ALL
EOF

# GRUB
sed -i 's|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT="slab_nomerge init_on_alloc=1 init_on_free=1 page_poison=1 random.trust_cpu=off random.trust_bootloader=off pti=on page_alloc.shuffle=1 spectre_v2=on spec_store_bypass_disable=on l1tf=full mds=full tsx=off tsx_async_abort=full retbleed=auto mitigations=auto vsyscall=none kvm.nx_huge_pages=force iommu=force intel_iommu=on amd_iommu=on efi=disable_early_pci_dma module.sig_enforce=1 lockdown=confidentiality quiet ipv6.disable=1 loglevel=0 apparmor=1 security=apparmor"|' /etc/default/grub
update-grub
chown root:root /etc/default/grub
chmod 640 /etc/default/grub

# SYSCTL
cat > /usr/lib/sysctl.d/sysctl.conf << 'EOF'
dev.tty.ldisc_autoload=0
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
vm.unprivileged_userfaultfd = 0
vm.swappiness = 0
vm.overcommit_memory = 2
vm.overcommit_ratio = 100
vm.panic_on_oom = 1
EOF
sysctl --system

# MODULES
cat > /etc/modprobe.d/harden.conf << 'EOF'
blacklist ax25
install ax25 /bin/false
blacklist can
install can /bin/false
blacklist dccp
install dccp /bin/false
blacklist decnet
install decnet /bin/false
blacklist econet
install econet /bin/false
blacklist ipx
install ipx /bin/false
blacklist netrom
install netrom /bin/false
blacklist p8022
install p8022 /bin/false
blacklist p8023
install p8023 /bin/false
blacklist psnap
install psnap /bin/false
blacklist rds
install rds /bin/false
blacklist rose
install rose /bin/false
blacklist sctp
install sctp /bin/false
blacklist tipc
install tipc /bin/false
blacklist x25
install x25 /bin/false
blacklist atm
install atm /bin/false
blacklist kvm
install kvm /bin/false
blacklist kvm_intel
install kvm_intel /bin/false
blacklist kvm_amd
install kvm_amd /bin/false
blacklist vboxdrv
install vboxdrv /bin/false
blacklist vboxnetadp
install vboxnetadp /bin/false
blacklist vboxnetflt
install vboxnetflt /bin/false
blacklist vmmon
install vmmon /bin/false
blacklist vmw_vmci
install vmw_vmci /bin/false
blacklist xen
install xen /bin/false
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
blacklist gfs2
install gfs2 /bin/false
blacklist floppy
install floppy /bin/false
blacklist firewire-core
install firewire-core /bin/false
blacklist usb_f_ecm
install usb_f_ecm /bin/false
blacklist usb_f_rndis
install usb_f_rndis /bin/false
blacklist mac80211
install mac80211 /bin/false
blacklist cfg80211
install cfg80211 /bin/false
blacklist iwlwifi
install iwlwifi /bin/false
blacklist ath*
install ath* /bin/false
blacklist brcmsmac
install brcmsmac /bin/false
blacklist brcmfmac
install brcmfmac /bin/false
blacklist rtl8*
install rtl8* /bin/false
blacklist rtl88*
install rtl88* /bin/false
blacklist rt2800*
install rt2800* /bin/false
blacklist mt76*
install mt76* /bin/false
blacklist bluetooth
install bluetooth /bin/false
blacklist btusb
install btusb /bin/false
blacklist btrtl
install btrtl /bin/false
blacklist btintel
install btintel /bin/false
blacklist btbcm
install btbcm /bin/false
blacklist usb_storage
install usb_storage /bin/false
blacklist uas
install uas /bin/false
blacklist lp
install lp /bin/false
blacklist ppdev
install ppdev /bin/false
blacklist parport
install parport /bin/false
blacklist hamradio
install hamradio /bin/false
blacklist af_802154
install af_802154 /bin/false
blacklist firewire-ohci
install firewire-ohci /bin/false
blacklist raw1394
install raw1394 /bin/false
blacklist jfs
install jfs /bin/false
blacklist reiserfs
install reiserfs /bin/false
blacklist dvb*
install dvb* /bin/false
blacklist r820t
install r820t /bin/false
blacklist rtl283*
install rtl283* /bin/false
blacklist rtl2830
install rtl2830 /bin/false
blacklist rtl2832
install rtl2832 /bin/false
blacklist rtl2838
install rtl2838 /bin/false
blacklist joydev
install joydev /bin/false
blacklist mousedev
install mousedev /bin/false
blacklist tap
install tap /bin/false
blacklist tun
install tun /bin/false
blacklist video1394
install video1394 /bin/false
blacklist garmin_gps
install garmin_gps /bin/false
blacklist gnss
install gnss /bin/false
blacklist gnss-serial
install gnss-serial /bin/false
blacklist gnss-usb
install gnss-usb /bin/false
EOF

# MOUNTS
echo "                                    
/dev/mapper/lvg-root                      /                          ext4       defaults,noatime,nodev,errors=remount-ro 0 1
/dev/mapper/lvg-home                      /home                      ext4       defaults,noatime,nodev,nosuid 0 2
/dev/mapper/lvg-run--shm                  /run/shm                   ext4       defaults,noatime,nodev,nosuid,noexec 0 2
/dev/mapper/lvg-tmp                       /tmp                       ext4       defaults,noatime,nodev,nosuid,noexec 0 2
/dev/mapper/lvg-usr                       /usr                       ext4       defaults,noatime,nodev,ro 0 2
/dev/mapper/lvg-var                       /var                       ext4       defaults,noatime,nodev,nosuid 0 2
/dev/mapper/lvg-var--log                  /var/log                   ext4       defaults,noatime,nodev,nosuid,noexec 0 2
/dev/mapper/lvg-var--log--audit           /var/log/audit             ext4       defaults,noatime,nodev,nosuid,noexec 0 2
/dev/mapper/lvg-var--tmp                  /var/tmp                   ext4       defaults,noatime,nodev,nosuid,noexec 0 2
proc                                      /proc                      proc       defaults,noatime,nodev,nosuid,noexec,hidepid=2 0 0
tmpfs                                     /run                       tmpfs      defaults,noatime,nodev,nosuid,noexec,mode=0755 0 0
tmpfs                                     /tmp                       tmpfs      defaults,noatime,nodev,nosuid,noexec,mode=1777 0 0
tmpfs                                     /var/tmp                   tmpfs      defaults,noatime,nodev,nosuid,noexec,bind,mode=1777
tmpfs                                     /dev/shm                   tmpfs      defaults,noatime,noexec,nosuid,mode=1777 0 0
udev                                      /dev                       devtmpfs   defaults,noatime,noexec,nosuid,noatime 0 0                              
devpts                                    /dev/pts                   devpts     defaults,noatime,noexec,nosuid,noatime,newinstance,ptmxmode=0666 0 0
" >> /etc/fstab

sed -i 's|^UUID=\([A-Za-z0-9-]\+\)[[:space:]]\+/boot/efi[[:space:]]\+vfat.*|UUID=\1                           /boot/efi                  vfat       noatime,nodev,nosuid,noexec,umask=0077 0 1|' /etc/fstab  

# PERMISSIONS
cd /etc
chown root:root group group- passwd passwd- security iptables default sudoers fstab hosts.allow hosts.deny hosts host.conf
chmod 0644 /etc/passwd
chmod 0644 /etc/group
chmod 0640 /etc/shadow
chmod 0640 /etc/gshadow
chmod 0600 /etc/passwd-
chmod 0600 /etc/group-
chmod 0600 /etc/shadow-
chmod 0640 /etc/gshadow-
chmod 0640 /etc/fstab
chmod 0440 /etc/sudoers 
chmod 0600 /root/.bashrc
chmod 0600 /root/.profile
chmod 0600 /etc/security
chown dev /home/dev
chmod 0700 /home/dev
chmod 0700 /root 
chmod 0700 /boot  
chown root:root /boot/grub/grub.cfg
chmod 0400 /boot/grub/grub.cfg
chmod -R 0400 /etc/iptables
chown root:root /var/run/dbus
chmod 0750 /var/run/dbus
chown root:root /run/systemd
chmod 0750 /run/systemd
chmod 0644 /etc/hosts.allow
chmod 0644 /etc/hosts.deny
chown root:root /etc/security/opasswd
chmod 0600 /etc/security/opasswd
chown root:adm -R /var/log
chmod -R 0640 /var/log
cd

# LOCKDOWN
find / -perm -4000 -exec chmod u-s {} \;
find / -perm -4000 -exec chmod g-s {} \;
find / -perm -2000 -exec chmod u-s {} \;
find / -perm -2000 -exec chmod g-s {} \;
chmod u+s /usr/bin/sudo
chmod u+s /bin/sudo
apt clean
apt autopurge 
apt purge "$(dpkg -l | grep '^rc' | awk '{print $2}')"
rm -r /etc/ssh
rm -r /usr/lib/ssh*
chattr +i /etc/fstab
chattr +i /etc/adduser.conf
chattr +i /etc/group
chattr +i /etc/group-
chattr +i /etc/hosts
chattr +i /etc/host.conf
chattr +i /etc/hosts.allow
chattr +i /etc/hosts.deny
chattr +i /etc/login.defs
chattr +i /etc/default/grub
chattr +i /etc/passwd
chattr +i /etc/passwd-
chattr +i /etc/gshadow-
chattr +i /etc/gshadow
chattr -R +i /etc/sudoers*
chattr +i /root/.bashrc
chattr +i /etc/shadow
chattr +i /etc/shadow-
chattr +i /etc/shells
chattr -R +i /etc/pam.d
chattr +i /usr/lib/sysctl.d/sysctl.conf
chattr -R +i /etc/modprobe.d
chattr +i /etc/services
chattr +i /etc/sudoers
chattr -R +i /etc/security
chattr -R +i /etc/iptables
chattr +i /etc/conf
chattr -R +i /etc/opensnitchd

echo "HARDENING SCRIPT COMPLETED"
