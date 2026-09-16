#!/usr/bin/env python3
"""External HTTPS/content/version/TLS-expiry gate. No credentials, no mutations."""
import json, os, socket, ssl, sys, time, urllib.request

def check(domain, marker, expected=None):
    context = ssl.create_default_context()
    with socket.create_connection((domain, 443), timeout=15) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as conn:
            expires = ssl.cert_time_to_seconds(conn.getpeercert()['notAfter'])
    days = (expires - time.time()) / 86400
    if days < 14:
        raise RuntimeError(f'{domain}: certificate expires in {days:.1f} days')
    for route in ['/', '/health', '/version']:
        with urllib.request.urlopen(f'https://{domain}{route}', timeout=20) as response:
            if response.status != 200 or response.url != f'https://{domain}{route}':
                raise RuntimeError(f'{domain}{route}: unexpected status or redirect')
            body = response.read().decode()
        if route == '/':
            if marker not in body or 'ZeroCreds' not in body:
                raise RuntimeError(f'{domain}: wrong landing content/language')
        else:
            data = json.loads(body)
            if route == '/health' and data.get('ok') is not True:
                raise RuntimeError(f'{domain}: unhealthy backend')
            if route == '/version' and expected and data.get('commit') != expected:
                raise RuntimeError(f'{domain}: unexpected deployed commit')
    print(f'{domain}: HTTPS, landing, health, version OK; TLS {days:.0f} days remaining')

if __name__ == '__main__':
    failed = False
    for domain, marker in [('zerocreds.ru', 'Данные уходят'), ('zerocreds.com', 'Credentials go straight')]:
        try:
            check(domain, marker, os.environ.get('EXPECTED_COMMIT'))
        except Exception as exc:
            failed = True
            print(f'FAIL {domain}: {exc}', file=sys.stderr)
    sys.exit(1 if failed else 0)
