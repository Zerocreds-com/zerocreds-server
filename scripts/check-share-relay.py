#!/usr/bin/env python3
"""Production smoke test for the public relay; creates no real credential."""

import json
import secrets
import urllib.error
import urllib.request

BASE = 'https://zerocreds.ru/api/share-relay/sessions'
share_id = secrets.token_hex(16)
owner_token = secrets.token_hex(32)


def request(method, url, payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    headers = {'Content-Type': 'application/json'}
    if method == 'DELETE':
        headers['Authorization'] = f'Bearer {owner_token}'
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=10) as response:
        return response.status, json.load(response)


status, body = request('POST', BASE, {
    'id': share_id, 'owner_token': owner_token, 'ttl_minutes': 1,
})
assert status == 201 and body['share_id'] == share_id
status, body = request('DELETE', f'{BASE}/{share_id}')
assert status == 200 and body['status'] == 'cancelled'
try:
    request('GET', f'{BASE}/{share_id}/poll')
except urllib.error.HTTPError as error:
    assert error.code == 410
else:
    raise AssertionError('cancelled relay share remained available')
print('public relay create/cancel smoke verified')
