#!/usr/bin/env bash
# setup-firewall-fail2ban.sh
# Safe bootstrap: enable UFW, set default deny incoming, allow specified SSH/IP, install and configure fail2ban, enable auditd.
# Run as root or with sudo.

set -euo pipefail

confirm() {
  read -r -p "$1 [y/N]: " resp
  case "$resp" in
    [yY][eE][sS]|[yY]) return 0 ;;
    *) return 1 ;;
  esac
}

echo "== DevSecOps: UFW + Fail2Ban + auditd bootstrap =="
echo
if ! confirm "Proceed with the bootstrap?"; then
  echo "Aborted by user"; exit 1
fi

read -r -p "Enter your SSH TCP port (example: 2222) : " SSH_PORT
if [[ -z "$SSH_PORT" ]]; then
  echo "No port entered. Using default 22"
  SSH_PORT=22
fi

read -r -p "Do you want to restrict SSH to a single admin IP? (recommended) [y/N]: " restrict_ip
ADMIN_CIDR=""
if [[ "$restrict_ip" =~ ^([yY][eE][sS]|[yY])$ ]]; then
  read -r -p "Enter admin IP in CIDR format (example 203.0.113.5/32): " ADMIN_CIDR
fi

# Ensure apt cache updated
apt-get update -y

# Install packages
DEBIAN_FRONTEND=noninteractive apt-get install -y ufw fail2ban auditd || { echo "APT install failed"; exit 1; }

# UFW defaults (safe ordering)
ufw default allow outgoing
ufw default deny incoming

# allow loopback
ufw allow in on lo

# Allow SSH (possibly restricted)
if [[ -n "$ADMIN_CIDR" ]]; then
  echo "Allowing SSH port $SSH_PORT only from $ADMIN_CIDR"
  ufw allow from "$ADMIN_CIDR" to any port "$SSH_PORT" proto tcp
else
  echo "Allowing SSH port $SSH_PORT from any IP (less secure)"
  ufw allow "$SSH_PORT"/tcp
fi

# Allow HTTP/HTTPS
ufw allow 80/tcp
ufw allow 443/tcp

# rate limit SSH
ufw limit "$SSH_PORT"/tcp

echo "Planned UFW rules:"
ufw status numbered || true

# Enable UFW after rules are added
if confirm "Enable UFW now? (ensure you have console access or allowed SSH rule)"; then
  ufw --force enable
  echo "UFW enabled"
else
  echo "UFW not enabled. You can enable later with 'sudo ufw enable'"
fi

# Configure Fail2Ban jail for SSH (local override)
mkdir -p /etc/fail2ban/jail.d
cat > /etc/fail2ban/jail.d/99-ufw-ssh.local <<'EOF'
[sshd]
enabled = true
port = SSH_PORT_PLACEHOLDER
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
findtime = 600
EOF

# Replace placeholder with actual port
sed -i "s/SSH_PORT_PLACEHOLDER/${SSH_PORT}/g" /etc/fail2ban/jail.d/99-ufw-ssh.local

# If admin CIDR provided, avoid banning yourself
if [[ -n "$ADMIN_CIDR" ]]; then
  sed -i "/^\[sshd\]/a ignoreip = 127.0.0.1/8 ${ADMIN_CIDR}" /etc/fail2ban/jail.d/99-ufw-ssh.local
fi

systemctl enable fail2ban
systemctl restart fail2ban
sleep 1
echo "Fail2Ban status (sshd):"
fail2ban-client status sshd || echo "fail2ban sshd status unavailable (check logs)"

# Enable auditd and add rules to watch sudoers
systemctl enable auditd
systemctl start auditd

cat > /etc/audit/rules.d/99-sudoers.rules <<'EOF'
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d -p wa -k sudoers_d_changes
EOF

# Load rules
augenrules --load || service auditd restart || true

echo
echo "=== Bootstrap complete ==="
echo "SSH Port: $SSH_PORT"
if [[ -n "$ADMIN_CIDR" ]]; then
  echo "SSH restricted to: $ADMIN_CIDR"
fi
echo "UFW status:"
ufw status verbose || true
echo
echo "Fail2Ban status (sshd):"
fail2ban-client status sshd || true
echo
echo "Audit rules (grep sudoers):"
auditctl -l | grep sudoers || true
echo
echo "Notes: If you enabled UFW and cannot SSH, use the VM console or cloud provider serial console to fix rules."
echo "To remove a ban: sudo fail2ban-client unban <ip>"
echo
echo "Done. Stay secure."
