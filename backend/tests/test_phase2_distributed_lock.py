"""
Phase 2 Distributed Lock Test Suite.
Validates:
- Mutual exclusion: Instance A acquires lock, Instance B cannot acquire.
- Safe release: Only owner with matching token can release; non-owner cannot.
- Heartbeat renewal: Owner can extend active lease.
- Stale-lock recovery: Expired lease can be acquired by a new instance.
"""

import time
import pytest
from unittest.mock import MagicMock
from app.services.scanner.distributed_lock import DistributedScanLock


class MockRedis:
    def __init__(self):
        self.store = {}
        self.ttls = {}

    def set(self, key, value, nx=False, ex=None):
        if nx and key in self.store:
            return False
        self.store[key] = value
        if ex:
            self.ttls[key] = ex
        return True

    def get(self, key):
        return self.store.get(key)

    def eval(self, script, numkeys, key, *args):
        # Emulate Lua renewal and release scripts
        if "del" in script:
            token = args[0]
            if self.store.get(key) == token:
                del self.store[key]
                self.ttls.pop(key, None)
                return 1
            return 0
        elif "expire" in script:
            token = args[0]
            ttl = int(args[1])
            if self.store.get(key) == token:
                self.ttls[key] = ttl
                return 1
            return 0
        return 0

    def ttl(self, key):
        if key not in self.store:
            return -2
        return self.ttls.get(key, -1)


class TestDistributedScanLock:
    def test_mutual_exclusion(self, monkeypatch):
        mock_r = MockRedis()
        monkeypatch.setattr("app.cache.cache.redis_client", mock_r)

        lock_a = DistributedScanLock(lock_key="test:scan:lock")
        lock_b = DistributedScanLock(lock_key="test:scan:lock")

        # Instance A acquires
        token_a = lock_a.acquire(lease_seconds=60)
        assert token_a is not None
        assert mock_r.store.get("test:scan:lock") == token_a

        # Instance B cannot acquire while lock is held
        token_b = lock_b.acquire(lease_seconds=60)
        assert token_b is None

    def test_owner_release_and_non_owner_rejection(self, monkeypatch):
        mock_r = MockRedis()
        monkeypatch.setattr("app.cache.cache.redis_client", mock_r)

        lock = DistributedScanLock(lock_key="test:scan:lock")
        token = lock.acquire(lease_seconds=60)
        assert token is not None

        # Non-owner fails to release
        wrong_token = "fake-token-not-owner"
        released_fake = lock.release(owner_token=wrong_token)
        assert released_fake is False
        assert mock_r.store.get("test:scan:lock") == token

        # Real owner successfully releases
        released_real = lock.release(owner_token=token)
        assert released_real is True
        assert "test:scan:lock" not in mock_r.store

    def test_heartbeat_lease_renewal(self, monkeypatch):
        mock_r = MockRedis()
        monkeypatch.setattr("app.cache.cache.redis_client", mock_r)

        lock = DistributedScanLock(lock_key="test:scan:lock")
        token = lock.acquire(lease_seconds=30)
        assert token is not None
        assert mock_r.ttls.get("test:scan:lock") == 30

        # Renew lease with heartbeat
        renewed = lock.renew(owner_token=token, lease_seconds=180)
        assert renewed is True
        assert mock_r.ttls.get("test:scan:lock") == 180

        # Wrong token renewal fails
        renewed_bad = lock.renew(owner_token="wrong-token", lease_seconds=180)
        assert renewed_bad is False

    def test_stale_lock_recovery(self, monkeypatch):
        mock_r = MockRedis()
        monkeypatch.setattr("app.cache.cache.redis_client", mock_r)

        lock_a = DistributedScanLock(lock_key="test:scan:lock")
        token_a = lock_a.acquire(lease_seconds=60)
        assert token_a is not None

        # Simulate expiration/crash where key is evicted by Redis
        del mock_r.store["test:scan:lock"]

        # Instance B can now recover and acquire the lock
        lock_b = DistributedScanLock(lock_key="test:scan:lock")
        token_b = lock_b.acquire(lease_seconds=60)
        assert token_b is not None
        assert token_b != token_a
