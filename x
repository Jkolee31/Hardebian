#!/usr/bin/env bash

set -euo pipefail

apt update#!/usr/bin/env bash

set -euo pipefail

apt update
apt install git curl wget ca-cert* gpg gnupg lsb-release apt-transport-https

# PRE CONFIG/AUDIT
echo 'APT::Get::AllowUnauthenticated "false";' >> /etc/apt/apt.conf.d/98-hardening
echo 'APT::Install-Suggests "false";' >> /etc/apt/apt.conf.d/98-hardening 
echo 'APT::Install-Recommends "false";' >> /etc/apt/apt.conf.d/98-hardening
echo 'DPkg
  {
      Pre-Invoke  { "mount -o remount,rw /usr" };
      Pre-Invoke  { "mount -o remount,rw /boot" };
  };' >> /etc/apt/apt.conf.d/99-remount 

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


systemctl disable debug-shell.service unattended-upgrades wpa_supplicant speech-dispatcher bluez bluetooth.service apport.service avahi-daemon.socket avahi-daemon.service cups-browsed cups.socket cups.path cups.service nvmf-autoconnect.service nvmefc-boot-connections.service pcscd.socket ModemManager.service systemd-pstore.service persist-autosave.service usbmuxd.service usb_modeswitch@.service usb-gadget.target mountnfs.service mountnfs-bootclean.service udisks2.service kexec.target systemd-kexec.service fprintd.service systemd-binfmt.service ctrl-alt-del.target rpcbind.target proc-sys-fs-binfmt_misc.mount proc-sys-fs-binfmt_misc.automount printer.target

systemctl mask debug-shell.service unattended-upgrades wpa_supplicant speech-dispatcher bluez bluetooth.service apport.service avahi-daemon.socket avahi-daemon.service cups-browsed cups.socket cups.path cups.service nvmf-autoconnect.service nvmefc-boot-connections.service pcscd.socket ModemManager.service systemd-pstore.service persist-autosave.service usbmuxd.service usb_modeswitch@.service usb-gadget.target mountnfs.service mountnfs-bootclean.service udisks2.service kexec.target systemd-kexec.service fprintd.service systemd-binfmt.service ctrl-alt-del.target rpcbind.target proc-sys-fs-binfmt_misc.mount proc-sys-fs-binfmt_misc.automount printer.target

apt purge -y  zram* pci* pmount* acpi* anacron* avahi* atmel* bc bind9* dns* fastfetch fonts-noto* fprint* isc-dhcp* lxc* docker* podman* xen* bochs* uml* vagrant* libssh* ssh* openssh* acpi* samba* winbind* qemu* libvirt* virt* cron* avahi* cup* print* rsync* virtual* sane* rpc* bind* nfs* blue* pp* spee* espeak* mobile* wireless* bc perl dictionaries-common doc-debian emacs* ethtool iamerican ibritish ienglish-common inet* ispell task-english util-linux-locales wamerican tasksel* vim* os-prober* netcat* libssh*


# FIREWALL (MULLVAD REQUIRED)
apt install iptables iptables-persistent netfilter-persistent
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
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A OUTPUT -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -o wg0-mullvad -j ACCEPT
iptables -A OUTPUT -p udp --dport 51820 -j ACCEPT
##########-PRE-INSTALL-RULES-######-REMOVE-##########
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p udp --dport 123 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
##########-POST-INSTALL-RULES-######-ADD-############
#iptables -A OUTPUT ! -o wg0-mullvad -m conntrack --ctstate NEW -p udp --dport 51820 -j ACCEPT
#iptables -A OUTPUT ! -o wg0-mullvad -m conntrack --ctstate NEW -j DROP
ip6tables -F
ip6tables -X
ip6tables -Z
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT DROP
iptables-save > /etc/iptables/rules.v4
iptables-save > /etc/iptables/rules.v6
netfilter-persistent save


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

Package: vagrant*
Pin: release *
Pin-Priority: -1
EOF

#INSTALL APPLICATIONS
apt update 
apt install -y pamu2fcfg libpam-u2f rsyslog chrony libpam-tmpdir fail2ban needrestart aptitude apt-listchanges acct sysstat rkhunter chkrootkit clamav clamdscan clamav-freshclam debsums apt-show-versions tiger wget gnupg lsb-release apt-transport-https unzip patch pulseaudio pulseaudio-utils pavucontrol alsa-utils lynis macchanger unhide tcpd haveged auditd fonts-liberation extrepo timeshift gnome-terminal gnome-brave-icon-theme breeze-gtk-theme bibata* tcpd macchanger mousepad xfce4 libxfce4ui-utils thunar xfce4-panel xfce4-session xfce4-settings xfce4-terminal xfconf xfdesktop4 xfwm4 xserver-xorg xinit xserver-xorg-legacy xfce4-pulse* xfce4-whisk* lightdm lightdm-gtk-greeter lightdm-gtk-greeter-settings opensnitch* python3-opensnitch*

#U2F
pamu2fcfg -u dev > /etc/u2f_mappings
chmod 600 /etc/u2f_mappings
chown root:root /etc/u2f_mappings
chattr +i /etc/u2f_mappings

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
account   required    pam_access.so
account   required    pam_unix.so
EOF

cat >/etc/pam.d/common-password <<'EOF'
#%PAM-1.0
password  [success=1  default=ignore]  pam_unix.so obscure use_authtok try_first_pass yescrypt
password  requisite   pam_deny.so
EOF

cat >/etc/pam.d/common-auth <<'EOF'
#%PAM-1.0
auth      sufficient  pam_u2f.so authfile=/etc/u2f_mappings
auth      requisite   pam_deny.so
EOF


cat >/etc/pam.d/common-session <<'EOF'
#%PAM-1.0
session   required    pam_limits.so
session	  required    pam_env.so
session	  optional    pam_systemd.so
session   optional    pam_umask.so umask=077
session   required    pam_unix.so
EOF

cat >/etc/pam.d/common-session-noninteractive <<'EOF'
#%PAM-1.0
session   required    pam_limits.so
session	  required    pam_env.so
session	  optional    pam_systemd.so
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

cat >/etc/pam.d/login <<'EOF'
#%PAM-1.0
auth      optional    pam_faildelay.so delay=3000000
auth      requisite   pam_nologin.so
auth      include     common-auth
account   include     common-account
session   include     common-session
password  include     common-password
EOF

cat >/etc/pam.d/lightdm <<'EOF'
#%PAM-1.0
auth      requisite   pam_nologin.so
auth      include     common-auth
account   include     common-account
session   [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so close
session   include     common-session
session   [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so open
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
session	  required    pam_limits.so
session	  required    pam_unix.so
EOF

cat >/etc/pam.d/runuser-l <<'EOF'
#%PAM-1.0
auth	    include     runuser
session	  include     runuser
EOF

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
 { echo '*            -      maxlogins    1'
   echo 'root         -      maxlogins    5'
   echo '*           soft    priority     0'
   echo '*           hard    nproc        2048'
   echo 'root        hard    nproc        65536'
   echo '*           soft    core         0'
   echo '*           hard    core         unlimited'
  } > /etc/security/limits.conf
echo "ProcessSizeMax=0
Storage=none" >> /etc/systemd/coredump.conf
echo "ulimit -c 0" >> /etc/profile

echo "UMASK 077" >> /etc/login.defs
echo "umask 077" >> /etc/profile
echo "umask 077" >> /etc/bash.bashrc
echo "ALL: ALL" > /etc/hosts.deny
sed -i "/^SHELL=/ s/=.*\+/=\/usr\/sbin\/nologin/" /etc/default/useradd
sed -i "/^DSHELL=/ s/=.*\+/=\/usr\/sbin\/nologin/" /etc/adduser.conf
echo "-:ALL EXCEPT dev:tty1" > /etc/security/access.conf
echo "-:ALL EXCEPT dev:LOCAL" >> /etc/security/access.conf
echo "-:dev:ALL EXCEPT LOCAL" >> /etc/security/access.conf
echo "+:dev:tty1 tty2 tty3 tty4 tty5 tty6" >> /etc/security/access.conf
echo "-:root:ALL" >> /etc/security/access.conf
echo "-:ALL:ALL" >> /etc/security/access.conf

 # GRUB
sed -i 's|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT="slab_nomerge slab_debug=FZ init_on_alloc=1 init_on_free=1 randomize_kstack_offset=on vsyscall=none pti=on debugfs=off kfence.sample_interval=100 efi_pstore.pstore_disable=1 amd_iommu=force_isolation intel_iommu=on iommu=force iommu.passthrough=0 efi=disable_early_pci_dma random.trust_bootloader=off random.trust_cpu=off extra_latent_entropy iommu.strict=1 vdso32=0 page_alloc.shuffle=1 mitigations=auto,nosmt nosmt=force spectre_v2=on spectre_bhi=on spec_store_bypass_disable=on ssbd=force-on l1tf=full,force kvm-intel.vmentry_l1d_flush=always mds=full,nosmt tsx=off lockdown=confidentiality tsx_async_abort=full,nosmt kvm.nx_huge_pages=force l1d_flush=on mmio_stale_data=full,nosmt retbleed=auto,nosmt module.sig_enforce=1 kvm.mitigate_smt_rsb=1 gather_data_sampling=force spec_rstack_overflow=safe-ret reg_file_data_sampling=on ipv6.disable=1 loglevel=0 quiet audit=1 apparmor=1 security=apparmor audit=1"|' /etc/default/grub
update-grub
chown root:root /etc/default/grub
chmod 640 /etc/default/grub 

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
blacklist kvm_intel
blacklist kvm_amd
blacklist vboxdrv
blacklist vboxnetflt
blacklist vboxnetadp
blacklist vmw_vmci
blacklist vmmon
blacklist xen
blacklist xenfs
blacklist xen_blkfront
blacklist xen_netfront
blacklist af_802154
blacklist amdgpu
blacklist appletalk
blacklist ath9k
blacklist atm
blacklist asus_acpi
blacklist ax25
blacklist b43
blacklist bcm43xx
blacklist bluetooth
blacklist btusb
blacklist can
blacklist cdrom
blacklist cifs
blacklist cramfs
blacklist dccp
blacklist decnet
blacklist de4x5
blacklist dvb_core
blacklist dvb_usb_rtl2832u
blacklist dvb_usb_rtl28xxu
blacklist dvb_usb_v2
blacklist econet
blacklist eepro100
blacklist eth1394
blacklist exfat
blacklist fddi
blacklist firewire
blacklist firewire-core
blacklist firewire_core
blacklist firewire-ohci
blacklist firewire_ohci
blacklist firewire-sbp2
blacklist firewire_sbp2
blacklist floppy
blacklist freevxfs
blacklist garmin_gps
blacklist gfs2
blacklist gnss
blacklist gnss-mtk
blacklist gnss-serial
blacklist gnss-sirf
blacklist gnss-usb
blacklist gnss-ubx
blacklist hamradio
blacklist hfs
blacklist hfsplus
blacklist ib_ipoib
blacklist ipx
blacklist jffs2
blacklist jfs
blacklist joydev
blacklist ksmbd
blacklist lp
blacklist msr
blacklist n-hdlc
blacklist netrom
blacklist nfs
blacklist nfsv3
blacklist nfsv4
blacklist ntfs
blacklist nvidia
blacklist ohci1394
blacklist p8022
blacklist p8023
blacklist parport
blacklist pmt_class
blacklist pmt_telemetry
blacklist ppp_async
blacklist ppp_deflate
blacklist ppp_generic
blacklist pppoe
blacklist pppox
blacklist prism54
blacklist psnap
blacklist r820t
blacklist radeon
blacklist raw1394
blacklist rds
blacklist reiserfs
blacklist rose
blacklist rtl2830
blacklist rtl2832
blacklist rtl2832_sdr
blacklist rtl2838
blacklist rtl8187
blacklist sbp2
blacklist sctp
blacklist slhc
blacklist squashfs
blacklist sr_mod
blacklist tipc
blacklist tr
blacklist udf
blacklist usb_storage
blacklist uvcvideo
blacklist uinput
blacklist video1394
blacklist vivid
blacklist x25
EOF

# KERNEL
rm -r /etc/sysctl.d
rm -r /usr/lib/sysctl.d
echo "kernel.modules_disabled = 1
dev.tty.ldisc_autoload = 0
dev.tty.legacy_tiocsti = 0
fs.protected_fifos = 2
fs.protected_hardlinks = 1
fs.protected_regular = 2
fs.protected_symlinks = 1
fs.suid_dumpable = 0
kernel.core_uses_pid = 1
kernel.dmesg_restrict = 1
kernel.kexec_load_disabled = 1
kernel.kptr_restrict = 2
kernel.perf_event_paranoid = 3
kernel.printk = 3 3 3 3
kernel.randomize_va_space = 2
kernel.sysrq = 0
kernel.unprivileged_bpf_disabled = 1
kernel.unprivileged_userns_clone = 1
kernel.yama.ptrace_scope = 3
net.core.bpf_jit_harden = 2
net.ipv4.icmp_echo_ignore_all=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.ip_forward=0
net.ipv4.ipfrag_secret_interval=0
net.ipv4.ipfrag_time=0
net.ipv4.route.flush=1
net.ipv4.tcp_abc=0
net.ipv4.tcp_abort_on_overflow=1
net.ipv4.tcp_adv_win_scale=1
net.ipv4.tcp_app_win=0
net.ipv4.tcp_ecn_fallback=0
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_orphan_retries=2
net.ipv4.tcp_retries=5
net.ipv4.tcp_rfc1337=1
net.ipv4.tcp_syn_retries=5
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_thin_linear_timeouts=1
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_workaround_signed_windows=1
net.ipv4.udp_early_demux=1
net.ipv4.udp_wmem_min=8192
net.ipv4.conf.all.accept_local=0
net.ipv4.conf.default.accept_local=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.arp_evict_nocarrier=1
net.ipv4.conf.default.arp_evict_nocarrier=1
net.ipv4.conf.all.arp_filter=1
net.ipv4.conf.default.arp_filter=1
net.ipv4.conf.all.arp_ignore=2
net.ipv4.conf.default.arp_ignore=2
net.ipv4.conf.all.drop_gratuitous_arp=1
net.ipv4.conf.default.drop_gratuitous_arp=1
net.ipv4.conf.all.shared_media=0
net.ipv4.conf.default.shared_media=0
net.ipv4.conf.all.forwarding=0
net.ipv4.conf.default.forwarding=0
net.ipv4.conf.all.mc.forwarding=0
net.ipv4.conf.default.mc.forwarding=0
net.ipv4.conf.all.route_localnet=0
net.ipv4.conf.default.route_localnet=0
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.shared_media=0
net.ipv4.conf.default.shared_media=0
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
vm.unprivileged_userfaultfd=0
vm.mmap_min_addr=65536
vm.max_map_count=1048576
vm.swappiness=1
vm.mmap_rnd_bits=32
vm.mmap_rnd_compat_bits=16
" > /etc/sysctl.conf
sysctl --system

# PERMISSIONS
cd /etc
sudo chown root:root cron.hourly cron.daily cron.weekly cron.monthly cron.d group group- passwd passwd- security iptables default sudoers fstab hosts.allow hosts.deny hosts host.conf
sudo chmod 0644 /etc/passwd
sudo chmod 0644 /etc/group
sudo chmod 0640 /etc/shadow
sudo chmod 0640 /etc/gshadow
sudo chmod 0600 /etc/passwd-
sudo chmod 0600 /etc/group-
sudo chmod 0600 /etc/shadow-
sudo chmod 0640 /etc/gshadow-
sudo chmod 0640 /etc/sysctl.conf
sudo chmod 0640 /etc/logrotate.conf
sudo chmod 0640 /etc/fstab
sudo chmod 0440 /etc/sudoers 
sudo chmod 0600 /root/.bashrc
sudo chmod 0600 /root/.profile
sudo chmod 0600 /etc/security
sudo chmod 0600 /etc/crontab
sudo chown dev /home/dev
sudo chmod 0700 /home/dev
sudo chmod 0700 /root 
sudo chmod 0700 /boot  
sudo chown root:root /boot/grub/grub.cfg
sudo chmod 0400 /boot/grub/grub.cfg
sudo chmod 0400 /etc/iptables
sudo chown root:root /var/run/dbus
sudo chmod 0750 /var/run/dbus
sudo chown root:root /run/sshd
sudo chmod 0750 /run/sshd
sudo chown root:root /run/systemd
sudo chmod 0750 /run/systemd
sudo chmod 0644 /etc/hosts.allow
sudo chmod 0644 /etc/hosts.deny
sudo chown root:root /etc/security/opasswd
sudo chmod 0600 /etc/security/opasswd
sudo chown root:adm -R /var/log/
sudo chmod -R 640 /var/log/
sudo chmod 0600 /var/log/faillog
sudo chown root:root /etc/ssh/sshd_config
sudo chmod 0400 /etc/ssh/sshd_config
sudo chown root:root /etc/ssh/ssh_config
sudo chmod 0400 /etc/ssh/ssh_config
sudo chmod -f 0700 /etc/cron.monthly/*
sudo chmod -f 0700 /etc/cron.weekly/*
sudo chmod -f 0700 /etc/cron.daily/*
sudo chmod -f 0700 /etc/cron.hourly/*
sudo chmod -f 0700 /etc/cron.d/*
sudo chmod -f 0400 /etc/cron.allow
sudo chmod -f 0400 /etc/cron.deny
sudo chmod -f 0400 /etc/crontab
sudo chmod -f 0400 /etc/at.allow
sudo chmod -f 0400 /etc/at.deny
sudo chmod -f 0700 /etc/cron.daily
sudo chmod -f 0700 /etc/cron.weekly
sudo chmod -f 0700 /etc/cron.monthly
sudo chmod -f 0700 /etc/cron.hourly
sudo chmod -f 0700 /var/spool/cron
sudo chmod -f 0600 /var/spool/cron/*
sudo chmod -f 0700 /var/spool/at
sudo chmod -f 0600 /var/spool/at/*
cd

# MOUNTS
echo "
proc                                      /proc              proc       defaults,nosuid,noexec,nodev,hidepid=2 0 0
udev                                       /dev             devtmpfs    defaults,noatime,noexec,nosuid 0 0
tmpfs       				                       /run              tmpfs   	  defaults,nodev,nosuid,noexec,mode=0755 0 0
tmpfs      				                       /dev/shm            tmpfs   	  defaults,nodev,nosuid,noexec,mode=1777 0 0
tmpfs       				                       /tmp              tmpfs   	  defaults,nodev,nosuid,noexec,mode=1777 0 0
tmpfs       				                      /var/tmp   	       tmpfs   	  defaults,nodev,nosuid,noexec,mode=1777 0 0
" >> /etc/fstab

# LOCKDOWN
find / -perm -4000 -o -perm -2000 -exec sudo chmod a-s {} \; 2>/dev/null
find / -perm -4000 -exec sudo chmod u-s {} \;
find / -perm -4000 -exec sudo chmod g-s {} \;
find / -perm -2000 -exec sudo chmod u-s {} \;
find / -perm -2000 -exec sudo chmod g-s {} \;
sudo chmod u+s /usr/bin/sudo
sudo chmod u+s /bin/sudo
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
chattr -R +i /etc/security
chattr -R +i /etc/ssh

apt install git curl wget ca-cert* gpg gnupg lsb-release apt-transport-https

# PRE CONFIG/AUDIT
echo 'APT::Get::AllowUnauthenticated "false";' >> /etc/apt/apt.conf.d/98-hardening
echo 'APT::Install-Suggests "false";' >> /etc/apt/apt.conf.d/98-hardening 
echo 'APT::Install-Recommends "false";' >> /etc/apt/apt.conf.d/98-hardening
echo 'DPkg
  {
      Pre-Invoke  { "mount -o remount,rw /usr" };
      Pre-Invoke  { "mount -o remount,rw /boot" };
  };' >> /etc/apt/apt.conf.d/99-remount 

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


systemctl disable debug-shell.service unattended-upgrades wpa_supplicant speech-dispatcher bluez bluetooth.service apport.service avahi-daemon.socket avahi-daemon.service cups-browsed cups.socket cups.path cups.service nvmf-autoconnect.service nvmefc-boot-connections.service pcscd.socket ModemManager.service systemd-pstore.service persist-autosave.service usbmuxd.service usb_modeswitch@.service usb-gadget.target mountnfs.service mountnfs-bootclean.service udisks2.service kexec.target systemd-kexec.service fprintd.service systemd-binfmt.service ctrl-alt-del.target rpcbind.target proc-sys-fs-binfmt_misc.mount proc-sys-fs-binfmt_misc.automount printer.target

systemctl mask debug-shell.service unattended-upgrades wpa_supplicant speech-dispatcher bluez bluetooth.service apport.service avahi-daemon.socket avahi-daemon.service cups-browsed cups.socket cups.path cups.service nvmf-autoconnect.service nvmefc-boot-connections.service pcscd.socket ModemManager.service systemd-pstore.service persist-autosave.service usbmuxd.service usb_modeswitch@.service usb-gadget.target mountnfs.service mountnfs-bootclean.service udisks2.service kexec.target systemd-kexec.service fprintd.service systemd-binfmt.service ctrl-alt-del.target rpcbind.target proc-sys-fs-binfmt_misc.mount proc-sys-fs-binfmt_misc.automount printer.target

apt purge -y  zram* pci* pmount* acpi* anacron* avahi* atmel* bc bind9* dns* fastfetch fonts-noto* fprint* isc-dhcp* lxc* docker* podman* xen* bochs* uml* vagrant* libssh* ssh* openssh* acpi* samba* winbind* qemu* libvirt* virt* cron* avahi* cup* print* rsync* virtual* sane* rpc* bind* nfs* blue* pp* spee* espeak* mobile* wireless* bc perl dictionaries-common doc-debian emacs* ethtool iamerican ibritish ienglish-common inet* ispell task-english util-linux-locales wamerican tasksel* vim* os-prober* netcat* libssh*


# FIREWALL (MULLVAD REQUIRED)
apt install iptables iptables-persistent netfilter-persistent
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
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A OUTPUT -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i wg0-mullvad -j ACCEPT
iptables -A OUTPUT -o wg0-mullvad -j ACCEPT
iptables -A OUTPUT -p udp --dport 51820 -j ACCEPT
##########-PRE-INSTALL-RULES-######-REMOVE-##########
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p udp --dport 123 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
##########-POST-INSTALL-RULES-######-ADD-############
#iptables -A OUTPUT ! -o wg0-mullvad -m conntrack --ctstate NEW -p udp --dport 51820 -j ACCEPT
#iptables -A OUTPUT ! -o wg0-mullvad -m conntrack --ctstate NEW -j DROP
ip6tables -F
ip6tables -X
ip6tables -Z
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT DROP
iptables-save > /etc/iptables/rules.v4
iptables-save > /etc/iptables/rules.v6
netfilter-persistent save


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

Package: vagrant*
Pin: release *
Pin-Priority: -1
EOF

#INSTALL APPLICATIONS
apt update 
apt install -y pamu2fcfg libpam-u2f rsyslog chrony libpam-tmpdir fail2ban needrestart aptitude apt-listchanges apt-listbugs apt-listdifferences acct sysstat rkhunter chkrootkit clamav clamdscan clamav-freshclam debsums apt-show-versions tiger wget gnupg lsb-release apt-transport-https unzip patch pulseaudio pulseaudio-utils pavucontrol alsa-utils lynis macchanger unhide tcpd haveged auditd fonts-liberation extrepo timeshift gnome-terminal gnome-brave-icon-theme breeze-gtk-theme bibata* tcpd macchanger mousepad xfce4 libxfce4ui-utils thunar xfce4-panel xfce4-session xfce4-settings xfce4-terminal xfconf xfdesktop4 xfwm4 xserver-xorg xinit xserver-xorg-legacy xfce4-pulse* xfce4-whisk* lightdm lightdm-gtk-greeter lightdm-gtk-greeter-settings opensnitch* python3-opensnitch*

#U2F
pamu2fcfg -u dev > /etc/u2f_mappings
chmod 600 /etc/u2f_mappings
chown root:root /etc/u2f_mappings
chattr +i /etc/u2f_mappings

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
auth      sufficient  pam_u2f.so authfile=/etc/u2f_mappings
auth      [success=1  default=ignore]  pam_unix.so try_first_pass
auth      requisite   pam_deny.so
EOF


cat >/etc/pam.d/common-session <<'EOF'
#%PAM-1.0
session   required    pam_limits.so
session	  required    pam_env.so
session	  optional    pam_systemd.so
session   optional    pam_umask.so umask=077
session   required    pam_unix.so
EOF

cat >/etc/pam.d/common-session-noninteractive <<'EOF'
#%PAM-1.0
session   required    pam_limits.so
session	  required    pam_env.so
session	  optionaL    pam_systemd.so
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

cat >/etc/pam.d/login <<'EOF'
#%PAM-1.0
auth      optional    pam_faildelay.so delay=3000000
auth      requisite   pam_nologin.so
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
auth	    sufficient  pam_rootok.so
session	  required    pam_limits.so
session	  required    pam_unix.so
EOF

cat >/etc/pam.d/runuser-l <<'EOF'
#%PAM-1.0
auth	    include     runuser
session	  include     runuser
EOF

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
  } >> /etc/security/limits.conf
echo "ProcessSizeMax=0
Storage=none" >> /etc/systemd/coredump.conf
echo "ulimit -c 0" >> /etc/profile

echo "SHA_CRYPT_MIN_ROUNDS 10000
SHA_CRYPT_MAX_ROUNDS 65536" >> /etc/login.defs
sed -i 's/^UMASK.*/UMASK 077/' /etc/login.defs
echo "umask 077" >> /etc/profile
echo "umask 077" >> /etc/bash.bashrc
echo "ALL: LOCAL, 127.0.0.1" >> /etc/hosts.allow
echo "ALL: ALL" > /etc/hosts.deny
sed -i "/^SHELL=/ s/=.*\+/=\/usr\/sbin\/nologin/" /etc/default/useradd
sed -i "/^DSHELL=/ s/=.*\+/=\/usr\/sbin\/nologin/" /etc/adduser.conf
echo "-:dev:ALL EXCEPT LOCAL" >> /etc/security/access.conf
echo "-:root:ALL" >> /etc/security/access.conf

 # GRUB
sed -i 's|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT="slab_nomerge slab_debug=FZ init_on_alloc=1 init_on_free=1 randomize_kstack_offset=on vsyscall=none pti=on debugfs=off kfence.sample_interval=100 efi_pstore.pstore_disable=1 amd_iommu=force_isolation intel_iommu=on iommu=force iommu.passthrough=0 efi=disable_early_pci_dma random.trust_bootloader=off random.trust_cpu=off extra_latent_entropy iommu.strict=1 vdso32=0 page_alloc.shuffle=1 mitigations=auto,nosmt nosmt=force spectre_v2=on spectre_bhi=on spec_store_bypass_disable=on ssbd=force-on l1tf=full,force kvm-intel.vmentry_l1d_flush=always mds=full,nosmt tsx=off lockdown=confidentiality tsx_async_abort=full,nosmt kvm.nx_huge_pages=force l1d_flush=on mmio_stale_data=full,nosmt retbleed=auto,nosmt module.sig_enforce=1 kvm.mitigate_smt_rsb=1 gather_data_sampling=force spec_rstack_overflow=safe-ret reg_file_data_sampling=on ipv6.disable=1 loglevel=0 quiet audit=1 apparmor=1 security=apparmor audit=1"|' /etc/default/grub
update-grub
chown root:root /etc/default/grub
chmod 640 /etc/default/grub 

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
blacklist kvm_intel
blacklist kvm_amd
blacklist vboxdrv
blacklist vboxnetflt
blacklist vboxnetadp
blacklist vmw_vmci
blacklist vmmon
blacklist xen
blacklist af_802154
blacklist amdgpu
blacklist appletalk
blacklist ath9k
blacklist atm
blacklist asus_acpi
blacklist ax25
blacklist b43
blacklist bcm43xx
blacklist bluetooth
blacklist btusb
blacklist can
blacklist cdrom
blacklist cifs
blacklist cramfs
blacklist dccp
blacklist decnet
blacklist de4x5
blacklist dvb_core
blacklist dvb_usb_rtl2832u
blacklist dvb_usb_rtl28xxu
blacklist dvb_usb_v2
blacklist econet
blacklist eepro100
blacklist eth1394
blacklist exfat
blacklist fddi
blacklist firewire
blacklist firewire-core
blacklist firewire_core
blacklist firewire-ohci
blacklist firewire_ohci
blacklist firewire-sbp2
blacklist firewire_sbp2
blacklist floppy
blacklist freevxfs
blacklist garmin_gps
blacklist gfs2
blacklist gnss
blacklist gnss-mtk
blacklist gnss-serial
blacklist gnss-sirf
blacklist gnss-usb
blacklist gnss-ubx
blacklist hamradio
blacklist hfs
blacklist hfsplus
blacklist ib_ipoib
blacklist ipx
blacklist jffs2
blacklist jfs
blacklist joydev
blacklist ksmbd
blacklist lp
blacklist msr
blacklist n-hdlc
blacklist netrom
blacklist nfs
blacklist nfsv3
blacklist nfsv4
blacklist ntfs
blacklist nvidia
blacklist ohci1394
blacklist p8022
blacklist p8023
blacklist parport
blacklist pmt_class
blacklist pmt_telemetry
blacklist ppp_async
blacklist ppp_deflate
blacklist ppp_generic
blacklist pppoe
blacklist pppox
blacklist prism54
blacklist psnap
blacklist r820t
blacklist radeon
blacklist raw1394
blacklist rds
blacklist reiserfs
blacklist rose
blacklist rtl2830
blacklist rtl2832
blacklist rtl2832_sdr
blacklist rtl2838
blacklist rtl8187
blacklist sbp2
blacklist sctp
blacklist slhc
blacklist squashfs
blacklist sr_mod
blacklist tipc
blacklist tr
blacklist udf
blacklist usb_storage
blacklist uvcvideo
blacklist uinput
blacklist video1394
blacklist vivid
blacklist x25
install kvm /bin/false
install kvm_intel /bin/false
install kvm_amd /bin/false
install vboxdrv /bin/false
install vboxnetflt /bin/false
install vboxnetadp /bin/false
install vmw_vmci /bin/false
install vmmon /bin/false
install xen /bin/false
install af_802154 /bin/false
install amdgpu /bin/false
install appletalk /bin/false	
install ath9k /bin/false
install atm /bin/false
install asus_acpi /bin/false	
install ax25 /bin/false
install b43 /bin/false
install bcm43xx /bin/false
install bluetooth /bin/false
install btusb /bin/false
install can /bin/false
install cdrom /bin/false
install cifs /bin/false
install cramfs /bin/false
install dccp /bin/false
install decnet /bin/false
install de4x5 /bin/false
install dvb_core /bin/false
install dvb_usb_rtl2832u /bin/false
install dvb_usb_rtl28xxu /bin/false
install dvb_usb_v2 /bin/false
install econet /bin/false
install eepro100 /bin/false
install eth1394 /bin/false 
install exfat /bin/false	
install fddi /bin/false
install firewire /bin/false
install firewire-core /bin/false
install firewire_core /bin/false	
install firewire-ohci /bin/false
install firewire_ohci /bin/false
install firewire-sbp2 /bin/false
install firewire_sbp2 /bin/false
install floppy /bin/false
install freevxfs /bin/false
install garmin_gps /bin/false
install gfs2 /bin/false
install gnss /bin/false
install gnss-mtk /bin/false
install gnss-serial /bin/false
install gnss-sirf /bin/false
install gnss-usb /bin/false
install gnss-ubx /bin/false
install hamradio /bin/false
install hfs /bin/false
install hfsplus /bin/false
install ib_ipoib /bin/false
install ipx /bin/false
install jffs2 /bin/false	
install jfs /bin/false
install joydev /bin/false
install ksmbd /bin/false
install lp /bin/false
install msr /bin/false
install n-hdlc /bin/false
install netrom /bin/false
install nfs /bin/false
install nfsv3 /bin/false
install nfsv4 /bin/false
install ntfs /bin/false
install nvidia /bin/false
install ohci1394 /bin/false
install p8022 /bin/false
install p8023 /bin/false	
install parport /bin/false
install pmt_class /bin/false	
install pmt_telemetry /bin/false	
install ppp_async /bin/false	
install ppp_deflate /bin/false
install ppp_generic /bin/false
install pppoe /bin/false	
install pppox /bin/false	
install prism54 /bin/false
install psnap /bin/false	
install r820t /bin/false	
install radeon /bin/false		
install raw1394 /bin/false
install rds /bin/false
install reiserfs /bin/false
install rose /bin/false
install rtl2830 /bin/false
install rtl2832 /bin/false
install rtl2832_sdr /bin/false
install rtl2838 /bin/false
install rtl8187 /bin/false
install sbp2 /bin/false
install sctp /bin/false
install slhc /bin/false
install squashfs /bin/false
install sr_mod /bin/false
install thunderbolt /bin/false
install tipc /bin/false
install tr /bin/false
install udf /bin/false
install usb_storage /bin/false
install uvcvideo /bin/false
install uinput /bin/false
install video1394 /bin/false
install vivid /bin/false
install x25 /bin/false
EOF

# KERNEL
rm -r /etc/sysctl.d
rm -r /usr/lib/sysctl.d
echo "#kernel.modules_disabled = 1
net.ipv4.ip_forward = 1
#user.max_user_namespaces = 0
dev.tty.ldisc_autoload = 0
dev.tty.legacy_tiocsti = 0
fs.protected_fifos = 2
fs.protected_hardlinks = 1
fs.protected_regular = 2
fs.protected_symlinks = 1
fs.suid_dumpable = 0
kernel.core_uses_pid = 1
kernel.dmesg_restrict = 1
kernel.kexec_load_disabled = 1
kernel.kptr_restrict = 2
kernel.perf_event_paranoid = 3
kernel.printk = 3 3 3 3
kernel.randomize_va_space = 2
kernel.sysrq = 0
kernel.unprivileged_bpf_disabled = 1
kernel.unprivileged_userns_clone = 1
kernel.yama.ptrace_scope = 3
net.core.bpf_jit_harden = 2
net.ipv4.conf.all.accept_local=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.all.arp_evict_nocarrier=1
net.ipv4.conf.all.arp_filter=1
net.ipv4.conf.all.arp_ignore=2
net.ipv4.conf.all.drop_gratuitous_arp=1
net.ipv4.conf.all.shared_media=0
net.ipv4.conf.all.forwarding=0
net.ipv4.conf.all.mc.forwarding=0
net.ipv4.conf.all.route_localnet=0
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.shared_media=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.default.shared_media=0
net.ipv4.icmp_echo_ignore_all=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.ip_forward=0
net.ipv4.ipfrag_secret_interval=0
net.ipv4.ipfrag_time=0
net.ipv4.route.flush=1
net.ipv4.tcp_abc=0
net.ipv4.tcp_abort_on_overflow=1
net.ipv4.tcp_adv_win_scale=1
net.ipv4.tcp_app_win=0
net.ipv4.tcp_ecn_fallback=0
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_orphan_retries=2
net.ipv4.tcp_retries=5
net.ipv4.tcp_rfc1337=1
net.ipv4.tcp_syn_retries=5
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_thin_linear_timeouts=1
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_workaround_signed_windows=1
net.ipv4.udp_early_demux=1
net.ipv4.udp_wmem_min=8192
net.ipv4.conf.*.accept_local=0
net.ipv4.conf.*.accept_redirects=0
net.ipv4.conf.*.accept_source_route=0
net.ipv4.conf.*.arp_evict_nocarrier=1
net.ipv4.conf.*.arp_filter=1
net.ipv4.conf.*.arp_ignore=2
net.ipv4.conf.*.drop_gratuitous_arp=1
net.ipv4.conf.*.forwarding=0
net.ipv4.conf.*.mc.forwarding=0
net.ipv4.conf.*.route_localnet=0
net.ipv4.conf.*.rp_filter=1
net.ipv4.conf.*.secure_redirects=0
net.ipv4.conf.*.send_redirects=0
net.ipv4.conf.*.shared_media=0
net.ipv4.conf.*.accept_redirects=0
net.ipv4.conf.*.accept_source_route=0
net.ipv4.conf.*.shared_media=0
net.ipv4.conf.*.send_redirects=0
net.ipv4.conf.*.shared_media=0
net.ipv6.conf.*.disable_ipv6=1
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
vm.unprivileged_userfaultfd=0
vm.mmap_min_addr=65536
vm.max_map_count=1048576
vm.swappiness=1
vm.mmap_rnd_bits=32
vm.mmap_rnd_compat_bits=16
" > /etc/sysctl.conf
sysctl --system

# PERMISSIONS
cd /etc
sudo chown root:root cron.hourly cron.daily cron.weekly cron.monthly cron.d group group- passwd passwd- security iptables default sudoers fstab hosts.allow hosts.deny hosts host.conf
sudo chmod 0644 /etc/passwd
sudo chmod 0644 /etc/group
sudo chmod 0640 /etc/shadow
sudo chmod 0640 /etc/gshadow
sudo chmod 0600 /etc/passwd-
sudo chmod 0600 /etc/group-
sudo chmod 0600 /etc/shadow-
sudo chmod 0640 /etc/gshadow-
sudo chmod 0640 /etc/sysctl.conf
sudo chmod 0640 /etc/logrotate.conf
sudo chmod 0640 /etc/fstab
sudo chmod 0440 /etc/sudoers 
sudo chmod 0600 /root/.bashrc
sudo chmod 0600 /root/.profile
sudo chmod 0600 /etc/security
sudo chmod 0600 /etc/crontab
sudo chmod 0600 /etc/anacrontab
sudo chown dev /home/dev
sudo chmod 0700 /home/dev
sudo chmod 0700 /root 
sudo chmod 0700 /boot 
sudo chmod 000 /usr/bin/kgcc
sudo chmod 000 /usr/bin/cc
sudo chmod 000 /usr/bin/gcc
sudo chmod 000 /usr/bin/*c++
sudo chmod 000 /usr/bin/*g++  
sudo chown root:root /boot/grub/grub.cfg
sudo chmod 0400 /boot/grub/grub.cfg
sudo chmod 0400 /etc/iptables
sudo chown root:root /var/run/dbus
sudo chmod 0750 /var/run/dbus
sudo chown root:root /run/sshd
sudo chmod 0750 /run/sshd
sudo chown root:root /run/systemd
sudo chmod 0750 /run/systemd
sudo chmod 0644 /etc/hosts.allow
sudo chmod 0644 /etc/hosts.deny
sudo chown root:root /etc/security/opasswd
sudo chmod 0600 /etc/security/opasswd
sudo chown root:adm -R /var/log/
sudo chmod -R 640 /var/log/
sudo chmod 0600 /var/log/faillog
sudo chown root:root /etc/ssh/sshd_config
sudo chmod 0400 /etc/ssh/sshd_config
sudo chown root:root /etc/ssh/ssh_config
sudo chmod 0400 /etc/ssh/ssh_config
sudo chmod -f 0700 /etc/cron.monthly/*
sudo chmod -f 0700 /etc/cron.weekly/*
sudo chmod -f 0700 /etc/cron.daily/*
sudo chmod -f 0700 /etc/cron.hourly/*
sudo chmod -f 0700 /etc/cron.d/*
sudo chmod -f 0400 /etc/cron.allow
sudo chmod -f 0400 /etc/cron.deny
sudo chmod -f 0400 /etc/crontab
sudo chmod -f 0400 /etc/at.allow
sudo chmod -f 0400 /etc/at.deny
sudo chmod -f 0700 /etc/cron.daily
sudo chmod -f 0700 /etc/cron.weekly
sudo chmod -f 0700 /etc/cron.monthly
sudo chmod -f 0700 /etc/cron.hourly
sudo chmod -f 0700 /var/spool/cron
sudo chmod -f 0600 /var/spool/cron/*
sudo chmod -f 0700 /var/spool/at
sudo chmod -f 0600 /var/spool/at/*
cd

# MOUNTS
echo "
udev                                       /dev             devtmpfs    defaults,noatime,noexec,nosuid 0 0
securityfs                          /sys/kernel/security   securityfs   defaults,nosuid,nodev,noexec 0 0
pstore                                /sys/fs/pstore         pstore     defaults,nosuid,nodev,noexec 0 0
systemd                            /sys/fs/cgroup/systemd    cgroup     defaults,nosuid,nodev,noexec 0 0
cgroup                                /sys/fs/cgroup         tmpfs      defaults,nosuid,nodev,noexec 0 0
efivarfs                         /sys/firmware/efi/efivars  efivarfs    defaults,nosuid,nodev,noexec 0 0
net_cls                            /sys/fs/cgroup/net_cls    cgroup     defaults,nosuid,nodev,noexec 0 0
proc                                       /proc              proc      defaults,nosuid,noexec,nodev,hidepid=2 0 0
devpts                                   /dev/pts             devpts    defaults,nosuid,noexec,newinstance,ptmxmode=0666 0 0
tmpfs                                /home/dev/.cache         tmpfs     defaults,nosuid,noexec,nodev,uid=1000,gid=1000,mode=0700 0 0
tmpfs       				                        /run              tmpfs   	defaults,nodev,nosuid,noexec,mode=0755 0 0
tmpfs      				                        /dev/shm            tmpfs   	defaults,nodev,nosuid,noexec,mode=1777 0 0
tmpfs       				                        /tmp              tmpfs   	defaults,nodev,nosuid,noexec,mode=1777 0 0
tmpfs       				                      /var/tmp   	        tmpfs   	defaults,nodev,nosuid,noexec,mode=1777 0 0
" >> /etc/fstab

# LOCKDOWN
find / -perm -4000 -o -perm -2000 -exec sudo chmod a-s {} \; 2>/dev/null
find / -perm -4000 -exec sudo chmod u-s {} \;
find / -perm -4000 -exec sudo chmod g-s {} \;
find / -perm -2000 -exec sudo chmod u-s {} \;
find / -perm -2000 -exec sudo chmod g-s {} \;
sudo chmod u+s /usr/bin/sudo
sudo chmod u+s /bin/sudo
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
