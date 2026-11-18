import pytest

from security.password_reset import (
    new_token,
    token_valid,
    consume_token,
    reset_response,
    build_reset_url,
    revoke_sessions,
    redact_token,
    normalize_email
)


def test_token_length():
    assert len(new_token()) >= 32

def test_token_unique():
    assert new_token() != new_token()

def test_valid():
    import hashlib
    record = {'token_hash': hashlib.sha256(b'tok').hexdigest(), 'expires': 100, 'used': False, 'pw_hash': 'p1'}
    assert token_valid(record, 'tok', 50, 'p1') is True

def test_expired():
    import hashlib
    record = {'token_hash': hashlib.sha256(b'tok').hexdigest(), 'expires': 40, 'used': False, 'pw_hash': 'p1'}
    assert token_valid(record, 'tok', 50, 'p1') is False

def test_used():
    import hashlib
    record = {'token_hash': hashlib.sha256(b'tok').hexdigest(), 'expires': 100, 'used': True, 'pw_hash': 'p1'}
    assert token_valid(record, 'tok', 50, 'p1') is False

def test_wrong_token():
    import hashlib
    record = {'token_hash': hashlib.sha256(b'tok').hexdigest(), 'expires': 100, 'used': False, 'pw_hash': 'p1'}
    assert token_valid(record, 'bad', 50, 'p1') is False

def test_pw_mismatch():
    import hashlib
    record = {'token_hash': hashlib.sha256(b'tok').hexdigest(), 'expires': 100, 'used': False, 'pw_hash': 'p1'}
    assert token_valid(record, 'tok', 50, 'p2') is False

def test_consume():
    store = {'tok': {'used': False, 'expires': 100}}
    assert consume_token(store, 'tok', 50) is True

def test_consume_twice():
    store = {'tok': {'used': False, 'expires': 100}}
    assert consume_token(store, 'tok', 50) is True
    assert consume_token(store, 'tok', 50) is False

def test_same_response():
    assert reset_response(True) == reset_response(False)

def test_fixed_host():
    url = build_reset_url('tok', 'evil.example')
    assert 'evil.example' not in url
    assert 'app.example' in url

def test_redact():
    assert 'tok' not in redact_token('tok=abcdef')

def test_normalize_email():
    assert normalize_email(' A@B.COM ') == 'a@b.com'

def test_revoke():
    sessions = {'u': ['s1', 's2'], 'v': ['s3']}
    assert revoke_sessions(sessions, 'u') == 2
    assert sessions['u'] == []

def test_empty():
    assert token_valid({}, '', 50, 'p1') is False
