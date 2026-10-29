import logging
import time

from app.config import settings
from app.database import SessionLocal
from app.services.jobs import claim_next_job, process_job


logger = logging.getLogger("api_sentinel.worker")


def run_forever() -> None:
    logger.info("worker starting", extra={"worker": settings.worker_name})

    while True:
        db = SessionLocal()
        try:
            job = claim_next_job(db, settings.worker_name)
            if not job:
                db.commit()
                time.sleep(settings.worker_poll_seconds)
                continue

            db.commit()
            process_job(db, job)
            logger.info("job processed", extra={"job_id": job.id, "job_type": job.job_type})

        except Exception as exc:  # noqa: BLE001
            logger.exception("worker loop failure: %s", exc)
            time.sleep(settings.worker_poll_seconds)
        finally:
            db.close()


if __name__ == "__main__":
    run_forever()
