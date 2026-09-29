# CloudScope Operations & Reliability Architecture

## 1. Overview
CloudScope is engineered for multi-instance, distributed high availability. It decouples scan orchestration, locking, durable state, and API serving to ensure reliable continuous operations.

## 2. Distributed Scanner Lock (`cloudscope:scan:lock`)
To prevent concurrent duplicate scans across multiple container instances or worker processes:
- **Mutual Exclusion**: Implemented in `backend/app/services/scanner/distributed_lock.py` using Redis atomic `SET key val NX EX ttl`.
- **Unique Lease Ownership**: Every lock acquisition generates a cryptographically random UUID token (`token = uuid4()`).
- **Heartbeat & Lease Renewal**: An active scan spawns a background heartbeat thread every 10 seconds executing an atomic Redis Lua script:
  ```lua
  if redis.call('get', KEYS[1]) == ARGV[1] then
      return redis.call('expire', KEYS[1], ARGV[2])
  else
      return 0
  end
  ```
- **Safe Release**: When the scan completes, an atomic Lua script verifies the token matches before releasing the lock, preventing a worker from releasing another worker's lock.
- **Stale Lock Recovery**: If an instance crashes abruptly without releasing the lock, the 120-second lease TTL automatically expires the lock in Redis, preventing permanent deadlocks.

## 3. Durable Relational Store
Redis is treated strictly as an ephemeral cache and distributed lock coordinator. All mission-critical state is written to a durable relational database (SQLite for development, PostgreSQL for production):
- **`ScanRunModel`**: Complete scan execution record (scan ID, mode, trigger type, resolved/successful/failed regions, collector counts, error summary, start/completion timestamps).
- **`ScanSnapshotModel`**: Published immutable snapshots (snapshot ID, published timestamp, total resource counts, finding counts by severity).
- **`FindingStateModel`**: Finding lifecycle states across scans (ACTIVE, ACKNOWLEDGED, RESOLVED, SUPPRESSED, audit trail of who changed it and why).
- **`AuditEventModel`**: Immutable administrative audit logs with retention management.

## 4. Operations Overview Dashboard
The Operations Center (`/operations` in the UI, `GET /api/v1/operations/overview` on the backend) provides administrators with:
1. **Real-time Distributed Lock State**: Lock status, owner instance ID, acquisition timestamp, remaining TTL seconds.
2. **Scanner Engine State**: Active phase, scanning flag, mode, progress.
3. **Service Dependencies**: Health status of Neo4j, Redis, and Relational Database.
4. **Build & Process Telemetry**: Git commit SHA, uptime, app version.
5. **Durable Scan Run History**: Table of last 10 scans persisted across restarts.
6. **Administrative Audit Trail**: Live log of security actions with sanitized metadata inspection.
7. **Manual Scan Trigger**: Direct trigger with concurrency protection.
