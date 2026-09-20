"""Versioned transactional SQLite store for private case graph data."""

from contextlib import contextmanager
from datetime import datetime
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Iterable, Iterator, Mapping

from osint_lab.case_manifest import validate_case_id
from osint_lab.orchestrator.audit import AuditEntry, AuditEventType, AuditLog
from osint_lab.policies import SourceClass

from .models import (
    CaseEvent,
    CaseEventType,
    EntityNode,
    EntityRelation,
    GraphEntityType,
    GraphRelationType,
    GraphStatus,
    ReviewerDecisionEvent,
    ReviewDecisionValue,
    ReviewTarget,
    TimelineEvent,
)


SCHEMA_VERSION = 1


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _load(value: str) -> object:
    return json.loads(value)


def _within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def deterministic_entity_id(case_id: str, entity_type: GraphEntityType, canonical_value: str) -> str:
    token = f"{case_id}|{entity_type.value}|{canonical_value}"
    return "ent-" + hashlib.sha256(token.encode("utf-8")).hexdigest()[:24]


def deterministic_relation_id(
    case_id: str,
    source_entity_id: str,
    target_entity_id: str,
    relation_type: GraphRelationType,
) -> str:
    token = f"{case_id}|{source_entity_id}|{relation_type.value}|{target_entity_id}"
    return "rel-" + hashlib.sha256(token.encode("utf-8")).hexdigest()[:24]


class GraphStore:
    """One SQLite database per case, always below the private case root."""

    def __init__(
        self,
        *,
        repo_root: Path,
        case_root: Path,
        case_id: str,
        audit_log: AuditLog | None = None,
    ) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.case_root = Path(case_root).resolve()
        self.case_id = validate_case_id(case_id)
        if _within(self.case_root, self.repo_root) or _within(self.repo_root, self.case_root):
            raise ValueError("graph case root must be outside and disjoint from repository")
        self.directory = (self.case_root / self.case_id / "graph").resolve()
        if not _within(self.directory, self.case_root):
            raise ValueError("graph path escaped case root")
        self.path = self.directory / "knowledge_graph.sqlite3"
        self._audit_log = audit_log
        self.directory.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @property
    def schema_version(self) -> int:
        with self._connect() as connection:
            row = connection.execute("SELECT value FROM graph_meta WHERE key='schema_version'").fetchone()
        return int(row[0])

    @property
    def graph_version(self) -> int:
        with self._connect() as connection:
            row = connection.execute("SELECT value FROM graph_meta WHERE key='graph_version'").fetchone()
        return int(row[0])

    def add_batch(
        self,
        *,
        entities: Iterable[EntityNode] = (),
        relations: Iterable[EntityRelation] = (),
        timeline: Iterable[TimelineEvent] = (),
        events: Iterable[CaseEvent] = (),
    ) -> tuple[int, int]:
        entity_values = tuple(entities)
        relation_values = tuple(relations)
        timeline_values = tuple(timeline)
        event_values = tuple(events)
        before = self.graph_version
        with self.transaction() as connection:
            for entity in entity_values:
                self._upsert_entity(connection, entity)
            for relation in relation_values:
                self._upsert_relation(connection, relation)
            for event in timeline_values:
                self._insert_timeline(connection, event)
            for event in event_values:
                self._insert_case_event(connection, event)
            if any((entity_values, relation_values, timeline_values, event_values)):
                self._increment_version(connection)
        return before, self.graph_version

    def record_evidence(
        self,
        *,
        evidence_id: str,
        source_ref: str,
        independence_group: str,
        first_seen: datetime,
        last_seen: datetime,
        quality_score: float | None,
    ) -> None:
        with self.transaction() as connection:
            connection.execute(
                """INSERT INTO evidence(evidence_id,source_ref,independence_group,first_seen,last_seen,quality_score)
                   VALUES(?,?,?,?,?,?) ON CONFLICT(evidence_id) DO UPDATE SET
                   last_seen=excluded.last_seen, quality_score=COALESCE(excluded.quality_score,evidence.quality_score)""",
                (evidence_id, source_ref, independence_group, first_seen.isoformat(), last_seen.isoformat(), quality_score),
            )
            connection.execute(
                "INSERT INTO evidence_events(evidence_id,timestamp,payload) VALUES(?,?,?)",
                (evidence_id, last_seen.isoformat(), _json({"source_ref": source_ref,
                 "independence_group": independence_group, "quality_score": quality_score})),
            )
            self._increment_version(connection)

    def append_decision(self, decision: ReviewerDecisionEvent) -> None:
        if decision.case_id != self.case_id:
            raise ValueError("review decision belongs to another case")
        with self.transaction() as connection:
            if decision.previous_decision_ref:
                previous = connection.execute(
                    "SELECT target_type,target_id FROM reviewer_decisions WHERE decision_id=?",
                    (decision.previous_decision_ref,),
                ).fetchone()
                if previous is None or tuple(previous) != (decision.target_type.value, decision.target_id):
                    raise ValueError("previous decision must exist for the same target")
            connection.execute(
                """INSERT INTO reviewer_decisions
                   (decision_id,case_id,reviewer,timestamp,target_type,target_id,decision,notes,evidence_refs,previous_ref)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (decision.decision_id, decision.case_id, decision.reviewer, decision.timestamp.isoformat(),
                 decision.target_type.value, decision.target_id, decision.decision.value, decision.notes,
                 _json(decision.evidence_refs), decision.previous_decision_ref),
            )
            if decision.target_type is ReviewTarget.RELATION:
                status = {
                    ReviewDecisionValue.CONFIRM: GraphStatus.CONFIRMED.value,
                    ReviewDecisionValue.REJECT: GraphStatus.REJECTED.value,
                    ReviewDecisionValue.KEEP_OPEN: GraphStatus.POSSIBLE.value,
                }[decision.decision]
                updated = connection.execute(
                    "UPDATE relations SET status=?,reviewer_decision_id=? WHERE relation_id=?",
                    (status, decision.decision_id, decision.target_id),
                ).rowcount
                if updated != 1:
                    raise ValueError("reviewed relation was not found")
            else:
                status = {
                    ReviewDecisionValue.CONFIRM: "VERIFIED",
                    ReviewDecisionValue.REJECT: "REJECTED",
                    ReviewDecisionValue.KEEP_OPEN: "OPEN",
                }[decision.decision]
                connection.execute(
                    """INSERT INTO review_effects(target_type,target_id,status,decision_id)
                       VALUES(?,?,?,?) ON CONFLICT(target_type,target_id) DO UPDATE SET
                       status=excluded.status,decision_id=excluded.decision_id""",
                    (decision.target_type.value, decision.target_id, status, decision.decision_id),
                )
            event = CaseEvent(
                event_id="evt-" + hashlib.sha256(f"review|{decision.decision_id}".encode()).hexdigest()[:24],
                case_id=self.case_id,
                event_type=CaseEventType.REVIEW_DECISION,
                timestamp=decision.timestamp,
                subject_id=decision.target_id,
                evidence_refs=decision.evidence_refs,
                attributes={"decision_id": decision.decision_id, "decision": decision.decision.value},
            )
            self._insert_case_event(connection, event)
            if self._audit_log is not None:
                self._audit_log.append(AuditEntry(
                    audit_id="audit-" + hashlib.sha256(f"review|{decision.decision_id}".encode()).hexdigest()[:24],
                    case_id=self.case_id,
                    execution_id=f"review-{decision.decision_id}",
                    authorization_id=None,
                    agent_name="reviewer_decision_store",
                    source_class=SourceClass.LOCAL,
                    event_type=AuditEventType.REVIEW_DECISION,
                    decision=decision.decision.value,
                    timestamp=decision.timestamp,
                    message="Append-only reviewer decision recorded.",
                    metadata={"decision_id": decision.decision_id, "target_type": decision.target_type.value,
                              "target_id_sha256": hashlib.sha256(decision.target_id.encode()).hexdigest()},
                ))
            self._increment_version(connection)

    def decisions(self) -> tuple[ReviewerDecisionEvent, ...]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM reviewer_decisions ORDER BY timestamp,decision_id").fetchall()
        return tuple(ReviewerDecisionEvent(
            decision_id=row["decision_id"], case_id=row["case_id"], reviewer=row["reviewer"],
            timestamp=datetime.fromisoformat(row["timestamp"]), target_type=ReviewTarget(row["target_type"]),
            target_id=row["target_id"], decision=ReviewDecisionValue(row["decision"]), notes=row["notes"],
            evidence_refs=tuple(_load(row["evidence_refs"])), previous_decision_ref=row["previous_ref"],
        ) for row in rows)

    def record_pivot(self, *, fingerprint: str, entity_id: str, enricher_id: str, status: str,
                     hop: int, timestamp: datetime) -> bool:
        with self.transaction() as connection:
            try:
                connection.execute(
                    "INSERT INTO pivot_history(fingerprint,entity_id,enricher_id,status,hop,timestamp) VALUES(?,?,?,?,?,?)",
                    (fingerprint, entity_id, enricher_id, status, hop, timestamp.isoformat()),
                )
            except sqlite3.IntegrityError:
                return False
            self._increment_version(connection)
        return True

    def has_pivot(self, fingerprint: str) -> bool:
        with self._connect() as connection:
            row = connection.execute("SELECT 1 FROM pivot_history WHERE fingerprint=?", (fingerprint,)).fetchone()
        return row is not None

    def record_run(self, payload: Mapping[str, object]) -> None:
        with self.transaction() as connection:
            connection.execute(
                "INSERT INTO run_records(run_id,created_at,payload) VALUES(?,?,?)",
                (str(payload["run_id"]), str(payload["finished_at"]), _json(dict(payload))),
            )
            self._increment_version(connection)

    def snapshot(self) -> dict[str, object]:
        with self._connect() as connection:
            entities = [self._entity_from_row(row).to_dict() for row in connection.execute(
                "SELECT * FROM entities ORDER BY entity_type,canonical_value"
            )]
            relations = [self._relation_from_row(row).to_dict() for row in connection.execute(
                "SELECT * FROM relations ORDER BY relation_type,relation_id"
            )]
            timeline = [dict(row) for row in connection.execute(
                "SELECT * FROM timeline_events ORDER BY timestamp,event_id"
            )]
            for item in timeline:
                for key in ("entity_ids", "relation_ids", "evidence_refs"):
                    item[key] = _load(item[key])
            events = [dict(row) for row in connection.execute(
                "SELECT * FROM case_events ORDER BY timestamp,event_id"
            )]
            for item in events:
                item["evidence_refs"] = _load(item["evidence_refs"])
                item["attributes"] = _load(item["attributes"])
            review_effects = [dict(row) for row in connection.execute(
                "SELECT * FROM review_effects ORDER BY target_type,target_id"
            )]
        return {"schema_version": self.schema_version, "graph_version": self.graph_version,
                "case_id": self.case_id, "nodes": entities, "edges": relations,
                "timeline": timeline, "case_events": events,
                "reviewer_decisions": [item.to_dict() for item in self.decisions()],
                "review_effects": review_effects}

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS graph_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS schema_migrations(
                    version INTEGER PRIMARY KEY,applied_at TEXT NOT NULL,description TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS entities(
                    entity_id TEXT PRIMARY KEY,case_id TEXT NOT NULL,entity_type TEXT NOT NULL,
                    canonical_value TEXT NOT NULL,display_value TEXT NOT NULL,aliases TEXT NOT NULL,
                    first_seen TEXT NOT NULL,last_seen TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,
                    source_refs TEXT NOT NULL,evidence_refs TEXT NOT NULL,confidence REAL NOT NULL,status TEXT NOT NULL,
                    attributes TEXT NOT NULL,UNIQUE(case_id,entity_type,canonical_value));
                CREATE TABLE IF NOT EXISTS entity_events(
                    event_seq INTEGER PRIMARY KEY AUTOINCREMENT,entity_id TEXT NOT NULL,timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,payload TEXT NOT NULL,FOREIGN KEY(entity_id) REFERENCES entities(entity_id));
                CREATE TABLE IF NOT EXISTS relations(
                    relation_id TEXT PRIMARY KEY,case_id TEXT NOT NULL,source_entity_id TEXT NOT NULL,
                    target_entity_id TEXT NOT NULL,relation_type TEXT NOT NULL,first_seen TEXT NOT NULL,last_seen TEXT NOT NULL,
                    evidence_refs TEXT NOT NULL,source_refs TEXT NOT NULL,independence_groups TEXT NOT NULL,
                    confidence REAL NOT NULL,status TEXT NOT NULL,reasons TEXT NOT NULL,reviewer_decision_id TEXT,
                    attributes TEXT NOT NULL,UNIQUE(case_id,source_entity_id,target_entity_id,relation_type),
                    FOREIGN KEY(source_entity_id) REFERENCES entities(entity_id),
                    FOREIGN KEY(target_entity_id) REFERENCES entities(entity_id));
                CREATE TABLE IF NOT EXISTS relation_events(
                    event_seq INTEGER PRIMARY KEY AUTOINCREMENT,relation_id TEXT NOT NULL,timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,payload TEXT NOT NULL,FOREIGN KEY(relation_id) REFERENCES relations(relation_id));
                CREATE TABLE IF NOT EXISTS evidence(
                    evidence_id TEXT PRIMARY KEY,source_ref TEXT NOT NULL,independence_group TEXT NOT NULL,
                    first_seen TEXT NOT NULL,last_seen TEXT NOT NULL,quality_score REAL);
                CREATE TABLE IF NOT EXISTS evidence_events(
                    event_seq INTEGER PRIMARY KEY AUTOINCREMENT,evidence_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,payload TEXT NOT NULL,
                    FOREIGN KEY(evidence_id) REFERENCES evidence(evidence_id));
                CREATE TABLE IF NOT EXISTS timeline_events(
                    event_id TEXT PRIMARY KEY,case_id TEXT NOT NULL,entity_ids TEXT NOT NULL,relation_ids TEXT NOT NULL,
                    event_type TEXT NOT NULL,timestamp TEXT NOT NULL,timestamp_source TEXT NOT NULL,
                    evidence_refs TEXT NOT NULL,confidence REAL NOT NULL,description TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS reviewer_decisions(
                    decision_id TEXT PRIMARY KEY,case_id TEXT NOT NULL,reviewer TEXT NOT NULL,timestamp TEXT NOT NULL,
                    target_type TEXT NOT NULL,target_id TEXT NOT NULL,decision TEXT NOT NULL,notes TEXT NOT NULL,
                    evidence_refs TEXT NOT NULL,previous_ref TEXT,
                    FOREIGN KEY(previous_ref) REFERENCES reviewer_decisions(decision_id));
                CREATE TABLE IF NOT EXISTS review_effects(
                    target_type TEXT NOT NULL,target_id TEXT NOT NULL,status TEXT NOT NULL,decision_id TEXT NOT NULL,
                    PRIMARY KEY(target_type,target_id),
                    FOREIGN KEY(decision_id) REFERENCES reviewer_decisions(decision_id));
                CREATE TABLE IF NOT EXISTS case_events(
                    event_id TEXT PRIMARY KEY,case_id TEXT NOT NULL,event_type TEXT NOT NULL,timestamp TEXT NOT NULL,
                    subject_id TEXT NOT NULL,evidence_refs TEXT NOT NULL,attributes TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS pivot_history(
                    fingerprint TEXT PRIMARY KEY,entity_id TEXT NOT NULL,enricher_id TEXT NOT NULL,
                    status TEXT NOT NULL,hop INTEGER NOT NULL,timestamp TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS run_records(
                    run_id TEXT PRIMARY KEY,created_at TEXT NOT NULL,payload TEXT NOT NULL);
            """)
            connection.execute("INSERT OR IGNORE INTO graph_meta(key,value) VALUES('schema_version',?)",
                               (str(SCHEMA_VERSION),))
            connection.execute("INSERT OR IGNORE INTO graph_meta(key,value) VALUES('graph_version','0')")
            connection.execute(
                "INSERT OR IGNORE INTO schema_migrations(version,applied_at,description) VALUES(1,?,?)",
                (datetime.now().astimezone().isoformat(), "Initial durable knowledge graph schema"),
            )
            stored = int(connection.execute(
                "SELECT value FROM graph_meta WHERE key='schema_version'"
            ).fetchone()[0])
            if stored > SCHEMA_VERSION:
                raise RuntimeError("graph schema is newer than this application")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    @staticmethod
    def _increment_version(connection: sqlite3.Connection) -> None:
        connection.execute("UPDATE graph_meta SET value=CAST(value AS INTEGER)+1 WHERE key='graph_version'")

    def _upsert_entity(self, connection: sqlite3.Connection, value: EntityNode) -> None:
        if value.case_id != self.case_id:
            raise ValueError("entity belongs to another case")
        existing = connection.execute("SELECT * FROM entities WHERE entity_id=?", (value.entity_id,)).fetchone()
        action = "CREATE" if existing is None else "UPDATE"
        aliases = set(value.aliases)
        source_refs = set(value.source_refs)
        evidence_refs = set(value.evidence_refs)
        first_seen, created_at = value.first_seen, value.created_at
        if existing is not None:
            aliases.update(_load(existing["aliases"]))
            source_refs.update(_load(existing["source_refs"]))
            evidence_refs.update(_load(existing["evidence_refs"]))
            first_seen = min(first_seen, datetime.fromisoformat(existing["first_seen"]))
            created_at = min(created_at, datetime.fromisoformat(existing["created_at"]))
        connection.execute("""INSERT INTO entities VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(entity_id) DO UPDATE SET display_value=excluded.display_value,aliases=excluded.aliases,
            first_seen=excluded.first_seen,last_seen=excluded.last_seen,updated_at=excluded.updated_at,
            source_refs=excluded.source_refs,evidence_refs=excluded.evidence_refs,
            confidence=excluded.confidence,status=excluded.status,attributes=excluded.attributes""",
            (value.entity_id, value.case_id, value.entity_type.value, value.canonical_value, value.display_value,
             _json(sorted(aliases)), first_seen.isoformat(), value.last_seen.isoformat(), created_at.isoformat(),
             value.updated_at.isoformat(), _json(sorted(source_refs)), _json(sorted(evidence_refs)),
             value.confidence, value.status.value, _json(dict(value.attributes))))
        connection.execute("INSERT INTO entity_events(entity_id,timestamp,action,payload) VALUES(?,?,?,?)",
                           (value.entity_id, value.updated_at.isoformat(), action, _json(value.to_dict())))

    def _upsert_relation(self, connection: sqlite3.Connection, value: EntityRelation) -> None:
        if value.case_id != self.case_id:
            raise ValueError("relation belongs to another case")
        existing = connection.execute("SELECT * FROM relations WHERE relation_id=?", (value.relation_id,)).fetchone()
        action = "CREATE" if existing is None else "UPDATE"
        evidence_refs, source_refs, groups = set(value.evidence_refs), set(value.source_refs), set(value.independence_groups)
        first_seen = value.first_seen
        if existing is not None:
            evidence_refs.update(_load(existing["evidence_refs"]))
            source_refs.update(_load(existing["source_refs"]))
            groups.update(_load(existing["independence_groups"]))
            first_seen = min(first_seen, datetime.fromisoformat(existing["first_seen"]))
        connection.execute("""INSERT INTO relations VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(relation_id) DO UPDATE SET first_seen=excluded.first_seen,last_seen=excluded.last_seen,
            evidence_refs=excluded.evidence_refs,source_refs=excluded.source_refs,
            independence_groups=excluded.independence_groups,confidence=excluded.confidence,
            status=excluded.status,reasons=excluded.reasons,reviewer_decision_id=excluded.reviewer_decision_id,
            attributes=excluded.attributes""",
            (value.relation_id, value.case_id, value.source_entity_id, value.target_entity_id,
             value.relation_type.value, first_seen.isoformat(), value.last_seen.isoformat(),
             _json(sorted(evidence_refs)), _json(sorted(source_refs)), _json(sorted(groups)), value.confidence,
             value.status.value, _json(value.reasons), value.reviewer_decision_id, _json(dict(value.attributes))))
        connection.execute("INSERT INTO relation_events(relation_id,timestamp,action,payload) VALUES(?,?,?,?)",
                           (value.relation_id, value.last_seen.isoformat(), action, _json(value.to_dict())))

    def _insert_timeline(self, connection: sqlite3.Connection, value: TimelineEvent) -> None:
        if value.case_id != self.case_id:
            raise ValueError("timeline event belongs to another case")
        connection.execute("INSERT OR IGNORE INTO timeline_events VALUES(?,?,?,?,?,?,?,?,?,?)",
                           (value.event_id, value.case_id, _json(value.entity_ids), _json(value.relation_ids),
                            value.event_type.value, value.timestamp.isoformat(), value.timestamp_source,
                            _json(value.evidence_refs), value.confidence, value.description))

    def _insert_case_event(self, connection: sqlite3.Connection, value: CaseEvent) -> None:
        if value.case_id != self.case_id:
            raise ValueError("case event belongs to another case")
        connection.execute("INSERT OR IGNORE INTO case_events VALUES(?,?,?,?,?,?,?)",
                           (value.event_id, value.case_id, value.event_type.value, value.timestamp.isoformat(),
                            value.subject_id, _json(value.evidence_refs), _json(dict(value.attributes))))

    @staticmethod
    def _entity_from_row(row: sqlite3.Row) -> EntityNode:
        return EntityNode(entity_id=row["entity_id"], case_id=row["case_id"],
                          entity_type=GraphEntityType(row["entity_type"]), canonical_value=row["canonical_value"],
                          display_value=row["display_value"], aliases=tuple(_load(row["aliases"])),
                          first_seen=datetime.fromisoformat(row["first_seen"]),
                          last_seen=datetime.fromisoformat(row["last_seen"]),
                          created_at=datetime.fromisoformat(row["created_at"]),
                          updated_at=datetime.fromisoformat(row["updated_at"]),
                          source_refs=tuple(_load(row["source_refs"])), evidence_refs=tuple(_load(row["evidence_refs"])),
                          confidence=row["confidence"], status=GraphStatus(row["status"]),
                          attributes=_load(row["attributes"]))

    @staticmethod
    def _relation_from_row(row: sqlite3.Row) -> EntityRelation:
        return EntityRelation(relation_id=row["relation_id"], case_id=row["case_id"],
                              source_entity_id=row["source_entity_id"], target_entity_id=row["target_entity_id"],
                              relation_type=GraphRelationType(row["relation_type"]),
                              first_seen=datetime.fromisoformat(row["first_seen"]),
                              last_seen=datetime.fromisoformat(row["last_seen"]),
                              evidence_refs=tuple(_load(row["evidence_refs"])),
                              source_refs=tuple(_load(row["source_refs"])),
                              independence_groups=tuple(_load(row["independence_groups"])),
                              confidence=row["confidence"], status=GraphStatus(row["status"]),
                              reasons=tuple(_load(row["reasons"])), reviewer_decision_id=row["reviewer_decision_id"],
                              attributes=_load(row["attributes"]))
