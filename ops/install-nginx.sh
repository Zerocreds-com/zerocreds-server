#!/usr/bin/env bash
# Administrative bootstrap/update. Review configs before running as root on RU.
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root on the RU VM' >&2; exit 1; }
[[ "${DEPLOY_ENV:-}" == ru ]] || { echo 'DEPLOY_ENV=ru required' >&2; exit 1; }
DIR=$(cd "$(dirname "$0")" && pwd)
backup=$(mktemp -d /var/backups/zerocreds-nginx.XXXXXX)
chmod 700 "$backup"
cp -a /etc/nginx/sites-available "$backup/"
cp -a /etc/nginx/sites-enabled "$backup/"
restore() {
  cp -a "$backup/sites-available/." /etc/nginx/sites-available/
  for domain in zerocreds.ru zerocreds.com; do
    rm -f "/etc/nginx/sites-enabled/$domain"
    if [[ -e "$backup/sites-enabled/$domain" || -L "$backup/sites-enabled/$domain" ]]; then
      cp -a "$backup/sites-enabled/$domain" "/etc/nginx/sites-enabled/$domain"
    fi
  done
  nginx -t || true
  echo "Failed; previous configs restored. Backup: $backup" >&2
}
nginx -t
trap 'restore; exit 1' ERR
for domain in zerocreds.ru zerocreds.com; do
  install -m 644 "$DIR/nginx/$domain.conf" "/etc/nginx/sites-available/$domain"
  ln -sfn "/etc/nginx/sites-available/$domain" "/etc/nginx/sites-enabled/$domain"
done
nginx -t
install -o root -g root -m 755 "$DIR/zerocreds-nginx-apply" /usr/local/sbin/zerocreds-nginx-apply
/usr/local/sbin/zerocreds-nginx-apply
trap - ERR
# Only fixed commands, no wildcard arguments or user-owned executable as root.
printf '%s\n' 'vova ALL=(root) NOPASSWD: /usr/local/sbin/zerocreds-nginx-apply "", /usr/sbin/nginx -t, /usr/bin/journalctl -u nginx --no-pager -n 20' > "$backup/sudoers-candidate"
visudo -cf "$backup/sudoers-candidate"
install -o root -g root -m 440 "$backup/sudoers-candidate" /etc/sudoers.d/zerocreds-nginx
install -o root -g root -m 755 "$DIR/zerocreds-nginx-apply" /etc/letsencrypt/renewal-hooks/deploy/zerocreds-nginx
echo "Installed; rollback files: $backup"
