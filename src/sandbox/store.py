"""Bounded, single-tenant evidence storage shared by local API workers."""

import base64
import binascii
import io
import json
import re
import sqlite3
import struct
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from PIL import Image


class CapacityError(Exception):
    """The submission or storage quota is exhausted."""


class ReplayUnavailable(Exception):
    """The source scan has no retained offline archive."""


class EvidenceStore:
    retention = 3600
    deadline = 270
    queue_limit = 8
    concurrent_limit = 2
    rate_limit = 6
    history_limit = 24
    max_report_bytes = 8 * 1024**2
    max_image_bytes = 24 * 1024**2

    def __init__(self, directory: Path):
        directory = directory.resolve()
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        self.path = directory / "evidence.sqlite3"
        with self.connection() as db:
            db.execute("PRAGMA journal_mode=WAL").fetchone()
            db.executescript("""
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY, url TEXT NOT NULL, mode TEXT NOT NULL,
                    status TEXT NOT NULL, created REAL NOT NULL, started REAL,
                    finished REAL, error TEXT, report BLOB
                );
                CREATE TABLE IF NOT EXISTS images (
                    job TEXT REFERENCES jobs(id) ON DELETE CASCADE,
                    name TEXT, data BLOB NOT NULL, PRIMARY KEY(job, name)
                );
                CREATE TABLE IF NOT EXISTS image_aliases (
                    job TEXT NOT NULL, name TEXT NOT NULL, original TEXT NOT NULL,
                    PRIMARY KEY(job,name), FOREIGN KEY(job,original)
                        REFERENCES images(job,name) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS inputs (
                    job TEXT PRIMARY KEY REFERENCES jobs(id) ON DELETE CASCADE,
                    url TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS snapshots (
                    job TEXT PRIMARY KEY REFERENCES jobs(id) ON DELETE CASCADE,
                    bundle BLOB NOT NULL, metadata BLOB NOT NULL, source TEXT
                );
                CREATE TRIGGER IF NOT EXISTS discard_scan_input AFTER UPDATE OF status ON jobs
                WHEN NEW.status IN ('completed','failed','timed_out')
                BEGIN
                    DELETE FROM inputs WHERE job=NEW.id;
                END;
                CREATE TRIGGER IF NOT EXISTS discard_failed_snapshot AFTER UPDATE OF status ON jobs
                WHEN NEW.status IN ('failed','timed_out')
                BEGIN
                    DELETE FROM snapshots WHERE job=NEW.id;
                END;
            """)

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=8)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA foreign_keys=ON")
            with db:
                yield db
        finally:
            db.close()

    def _expire(self, db, now: float):
        db.execute("DELETE FROM jobs WHERE finished < ?", (now - self.retention,))
        db.execute("""UPDATE jobs SET status='timed_out', finished=?, error=?
                      WHERE status='running' AND started < ?""",
                   (now, "Analysis exceeded its execution deadline.", now - self.deadline - 10))
        db.execute("""UPDATE jobs SET status='timed_out', finished=?, error=?
                      WHERE status='queued' AND created < ?""",
                   (now, "Analysis expired in the queue.", now - self.retention))

    def enqueue(self, url: str, mode: str, *, replay_of: str | None = None) -> str:
        now = time.time()
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            self._expire(db, now)
            recent = db.execute("SELECT count(*) FROM jobs WHERE created >= ?", (now - 60,)).fetchone()[0]
            if recent >= self.rate_limit:
                raise CapacityError("Scan rate limit reached. Retry in one minute.")
            active = db.execute("SELECT count(*) FROM jobs WHERE status IN ('queued','running')").fetchone()[0]
            if active >= self.queue_limit:
                raise CapacityError("The sandbox queue is full.")
            snapshot = None
            if replay_of is not None:
                snapshot = db.execute("""SELECT s.bundle,s.metadata FROM snapshots s JOIN jobs j ON j.id=s.job
                                         WHERE s.job=? AND j.status='completed'""", (replay_of,)).fetchone()
                if snapshot is None:
                    raise ReplayUnavailable()
            # Free old completed evidence before admitting a new report.
            count = db.execute("SELECT count(*) FROM jobs").fetchone()[0]
            if count >= self.history_limit:
                db.execute("""DELETE FROM jobs WHERE id IN (SELECT id FROM jobs
                              WHERE finished IS NOT NULL ORDER BY finished LIMIT 1)""")
            job = uuid.uuid4().hex
            db.execute("INSERT INTO jobs(id,url,mode,status,created) VALUES (?,?,?,'queued',?)",
                       (job, url.partition("?")[0], mode, now))
            if snapshot is None:
                db.execute("INSERT INTO inputs(job,url) VALUES (?,?)", (job, url))
            else:
                # Retain the source independently of its lifetime while this job waits.
                db.execute("INSERT INTO snapshots VALUES(?,?,?,?)",
                           (job, snapshot["bundle"], snapshot["metadata"], replay_of))
        return job

    def claim(self) -> str | None:
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            self._expire(db, time.time())
            running = db.execute("SELECT count(*) FROM jobs WHERE status='running'").fetchone()[0]
            if running >= self.concurrent_limit:
                return None
            row = db.execute("SELECT id FROM jobs WHERE status='queued' ORDER BY created LIMIT 1").fetchone()
            if row:
                db.execute("UPDATE jobs SET status='running', started=? WHERE id=?", (time.time(), row["id"]))
                return row["id"]
        return None

    def status(self, job: str) -> dict | None:
        with self.connection() as db:
            row = db.execute("""SELECT id AS analysis_id,url,mode,status,created,started,
                                finished,error FROM jobs WHERE id=?""", (job,)).fetchone()
        return dict(row) if row else None

    def fail(self, job: str, status: str, message: str):
        with self.connection() as db:
            db.execute("""UPDATE jobs SET status=?,error=?,finished=? WHERE id=? AND status='running'""",
                       (status, message, time.time(), job))

    def input_url(self, job: str) -> str | None:
        with self.connection() as db:
            row = db.execute("SELECT url FROM inputs WHERE job=?", (job,)).fetchone()
        return row[0] if row else None

    def replay_input(self, job: str) -> tuple[bytes, dict, str]:
        with self.connection() as db:
            row = db.execute("SELECT bundle,metadata,source FROM snapshots WHERE job=? AND source IS NOT NULL",
                             (job,)).fetchone()
        if row is None:
            raise ReplayUnavailable()
        return row["bundle"], json.loads(row["metadata"]), row["source"]

    def complete(self, job: str, report: dict, *, snapshot: bytes | None = None):
        report = dict(report)
        if snapshot is not None and len(snapshot) > 28 * 1024**2:
            raise ValueError("Offline capture exceeds storage budget")
        report["replay_available"] = snapshot is not None
        if snapshot is None and report.get("capture", {}).get("replayed_from"):
            with self.connection() as db:
                report["replay_available"] = db.execute(
                    "SELECT 1 FROM snapshots WHERE job=? AND source IS NOT NULL", (job,)
                ).fetchone() is not None
        encoded = report.pop("screenshots", {})
        images = {}
        originals = {}
        aliases = {}
        total = 0
        if not isinstance(encoded, dict) or len(encoded) > 32:
            raise ValueError("Invalid screenshot set")
        for name, data in encoded.items():
            if not re.fullmatch(r"[\w.-]{1,64}", name, re.ASCII) or not isinstance(data, str):
                raise ValueError("Invalid screenshot")
            if len(data) > self.max_image_bytes * 4 // 3 + 4:
                raise ValueError("Oversize screenshot")
            if data in originals:
                original = originals[data]
                total += len(images[original])
                if total > self.max_image_bytes:
                    raise ValueError("Screenshot budget exceeded")
                aliases[name] = original
                continue
            try:
                image = base64.b64decode(data, validate=True)
            except binascii.Error as error:
                raise ValueError("Invalid screenshot encoding") from error
            if len(image) < 33 or not image.startswith(b"\x89PNG\r\n\x1a\n") or image[12:16] != b"IHDR":
                raise ValueError("Unexpected screenshot format")
            width, height = struct.unpack(">II", image[16:24])
            total += len(image)
            if not width or not height or width * height > 16_000_000 or total > self.max_image_bytes:
                raise ValueError("Screenshot budget exceeded")
            # Check the complete encoded artifact, including PNG chunk checksums.
            try:
                stream = io.BytesIO(image)
                with Image.open(stream, formats=["PNG"]) as png:
                    png.verify()
                # Pillow stops after the first IEND header. Its CRC must end this file.
                if stream.tell() != len(image) - 4 or not image.endswith(b"\x00\x00\x00\x00IEND\xaeB\x60\x82"):
                    raise ValueError("Invalid screenshot terminator")
                stream.seek(0)
                with Image.open(stream, formats=["PNG"]) as png:
                    if png.is_animated:
                        raise ValueError("Unexpected animated screenshot")
                    png.load()
            except (OSError, SyntaxError, ValueError) as error:
                raise ValueError("Invalid screenshot contents") from error
            images[name] = image
            originals[data] = name
        report["screenshots"] = {name: f"/api/sandbox/screenshot/{job}?view={name}" for name in encoded}
        # Worker observations are immutable once the terminal status is committed.
        payload = json.dumps(report, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode()
        if len(payload) > self.max_report_bytes:
            raise ValueError("Report budget exceeded")
        with self.connection() as db:
            updated = db.execute("""UPDATE jobs SET status='completed', finished=?, report=?
                                    WHERE id=? AND status='running'""", (time.time(), payload, job))
            if updated.rowcount:
                db.executemany("INSERT INTO images VALUES(?,?,?)", ((job, k, v) for k, v in images.items()))
                db.executemany("INSERT INTO image_aliases VALUES(?,?,?)", ((job, k, v) for k, v in aliases.items()))
                if report["replay_available"]:
                    metadata = json.dumps({"capture": report["capture"], "model": report.get("existing_model_prediction"),
                                           "behavior_profile": report.get("behavior_profile")})
                if snapshot is not None:
                    db.execute("INSERT INTO snapshots VALUES(?,?,?,NULL)", (job, snapshot, metadata))
                elif report["replay_available"]:
                    db.execute("UPDATE snapshots SET metadata=? WHERE job=?", (metadata, job))

    def report(self, job: str) -> dict | None:
        with self.connection() as db:
            row = db.execute("SELECT report FROM jobs WHERE id=?", (job,)).fetchone()
        return json.loads(row[0]) if row and row[0] else None

    def image(self, job: str, name: str) -> bytes | None:
        with self.connection() as db:
            row = db.execute("""SELECT data FROM images WHERE job=? AND name=COALESCE(
                                (SELECT original FROM image_aliases WHERE job=? AND name=?), ?)""",
                             (job, job, name, name)).fetchone()
        return row[0] if row else None
