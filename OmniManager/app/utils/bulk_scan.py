"""
Shared helper for bulk scanning multiple endpoints concurrently.
Uses ThreadPoolExecutor so WinRM calls happen in parallel without
blocking the web process.
"""
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

# Max simultaneous WinRM connections. Keep modest to avoid overwhelming
# the network or target hosts.
MAX_WORKERS = 5


def run_bulk_scan(app, endpoint_ids, scan_fn, label="scan"):
    """
    Spawn a background thread that fans out scan_fn(ep_id) across
    all endpoint_ids using a thread pool.

    scan_fn receives a single endpoint_id (int) and is called inside
    a fresh app context — it must load its own DB objects.
    """
    def _worker(ep_id):
        with app.app_context():
            try:
                scan_fn(ep_id)
            except Exception:
                logger.exception("Bulk %s worker crashed — endpoint_id=%s", label, ep_id)

    def _run_pool():
        logger.info("Bulk %s started — %d endpoints", label, len(endpoint_ids))
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futures = {pool.submit(_worker, eid): eid for eid in endpoint_ids}
            for future in as_completed(futures):
                eid = futures[future]
                exc = future.exception()
                if exc:
                    logger.error("Bulk %s future error — endpoint_id=%s: %s", label, eid, exc)
        logger.info("Bulk %s finished — %d endpoints", label, len(endpoint_ids))

    threading.Thread(target=_run_pool, daemon=True).start()
