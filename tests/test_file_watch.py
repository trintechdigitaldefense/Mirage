import os

from mirage.file_watch import FileAccessWatcher


def test_poll_does_not_hash_unchanged_file_or_emit_self_access(monkeypatch, tmp_path):
    target = tmp_path / "decoy.txt"
    target.write_text("original", encoding="utf-8")
    hash_calls = []
    events = []

    def fake_hash(path, max_bytes=65536):
        hash_calls.append(str(path))
        return "stable-hash"

    monkeypatch.setattr("mirage.file_watch._file_hash", fake_hash)
    watcher = FileAccessWatcher([str(target)], on_event=lambda **event: events.append(event))
    watcher.seed()
    watcher.poll_once()

    assert len(hash_calls) == 1
    assert events == []


def test_atime_advance_is_detected_without_rereading_file(monkeypatch, tmp_path):
    target = tmp_path / "decoy.txt"
    target.write_text("original", encoding="utf-8")
    hash_calls = []
    events = []

    def fake_hash(path, max_bytes=65536):
        hash_calls.append(str(path))
        return "stable-hash"

    monkeypatch.setattr("mirage.file_watch._file_hash", fake_hash)
    watcher = FileAccessWatcher([str(target)], on_event=lambda **event: events.append(event))
    watcher.seed()

    before = target.stat()
    future_atime = before.st_atime + 120
    os.utime(target, (future_atime, before.st_mtime))
    watcher.poll_once()

    assert len(hash_calls) == 1
    assert len(events) == 1
    assert events[0]["event_type"] == "canary_opened"
    assert events[0]["details"]["signal_quality"] == "atime"
