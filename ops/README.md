# Production topology and recovery

Both zerocreds.ru (Russian landing) and zerocreds.com (English landing) terminate TLS
on the RU VM and use the same localhost:3456 backend. Landing roots are respectively
`/home/vova/zerocreds-landing` and `/home/vova/zerocreds-com-landing`. There is no second
COM backend. The production workflow uses DEPLOY_HOST_RU/DEPLOY_USER_RU/DEPLOY_KEY.

As an administrator on RU, run `sudo DEPLOY_ENV=ru bash ops/install-nginx.sh` after
reviewing the two nginx configs. It backs up configs, validates before reload, restores
on failure, installs a root-owned no-argument helper and narrowly scoped sudo permissions.
Normal deployments run only the helper, not repository scripts as root. Nginx changes
require this separate administrative install. Never install the agent's GCP relay on RU.

The production deploy gates on tests, nginx validation, the running commit and external
HTTPS checks for both domains. The public monitor runs twice hourly in GitHub Actions
and fails for TLS errors, expiry within 14 days, wrong landing language or unhealthy API.
It does not create sessions or restart anything. A failed run saves nginx validation,
service state and the last 20 nginx journal lines. Subscribe to workflow failures in
GitHub for notifications; there is no new messaging integration. Scheduled Actions can
be delayed by GitHub and are not a hard 30-minute availability SLA.

Certbot's timer renews certificates; its deploy hook validates nginx before reloading or
starting it. Check `systemctl list-timers certbot.timer` and run `sudo certbot renew
--dry-run --non-interactive` for renewal validation. Test the hook separately with
`sudo /etc/letsencrypt/renewal-hooks/deploy/zerocreds-nginx`: the installed Certbot
version does not support `--run-deploy-hooks`. Never restart nginx in a retry loop.

Rollback: restore only the affected files from `/var/backups/zerocreds-nginx.*`, run
`sudo nginx -t`, then the root-owned helper. To roll back the application, check out the
previous release, `npm ci --omit=dev` in server, restart zerocreds-server, and run
`python3 scripts/check-public.py`. Do not restore the invalid GCP relay on RU.
