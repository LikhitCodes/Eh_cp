import hashlib
import json
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.models import AuditEvent


def _canonical_payload(entity_type: str, entity_id: str, event_type: str, actor: str, before: dict, after: dict) -> str:
    payload = {
        "entity_type": entity_type,
        "entity_id": entity_id,
        "event_type": event_type,
        "actor": actor,
        "before": before,
        "after": after,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def create_audit_event(
    db: Session,
    *,
    entity_type: str,
    entity_id: str,
    event_type: str,
    actor: str,
    before: Optional[dict] = None,
    after: Optional[dict] = None,
) -> AuditEvent:
    before_payload = before or {}
    after_payload = after or {}
    payload = _canonical_payload(entity_type, entity_id, event_type, actor, before_payload, after_payload)
    signature = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    event = AuditEvent(
        entity_type=entity_type,
        entity_id=entity_id,
        event_type=event_type,
        actor=actor,
        timestamp=datetime.now(timezone.utc),
        before=before_payload,
        after=after_payload,
        signature=signature,
    )
    db.add(event)
    db.flush()
    return event
