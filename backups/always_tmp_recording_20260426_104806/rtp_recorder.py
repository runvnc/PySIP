import json
import os
import re
import threading
import time
import wave
from pathlib import Path
from typing import Any, Optional, Tuple

from .codecs import get_decoder
from .codecs.codec_info import CodecInfo


RTP_TS_MOD = 2 ** 32
RTP_SEQ_MOD = 2 ** 16


def _truthy(value: Optional[str]) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on", "y"}


def _safe_name(value: Optional[str]) -> str:
    value = str(value or "unknown")
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value)
    return value[:160] or "unknown"


def _signed_delta(value: int, reference: int, bits: int) -> int:
    mod = 1 << bits
    half = 1 << (bits - 1)
    delta = (int(value) - int(reference)) & (mod - 1)
    if delta >= half:
        delta -= mod
    return delta


class RTPWavRecorder:
    """Diagnostic RTP recorder.

    Writes a mono 8kHz PCM16 WAV reconstructed on the RTP timestamp
    timeline, plus JSONL packet metadata. This is intentionally positioned at
    RTP packet boundaries rather than application audio queues.
    """

    def __init__(self, wav_path: str | Path, codec: CodecInfo, direction: str):
        self.wav_path = Path(wav_path)
        self.jsonl_path = self.wav_path.with_suffix(".jsonl")
        self.codec = codec
        self.direction = direction
        self.decoder = get_decoder(codec)
        self.sample_rate = int(codec.rate or 8000)
        self.sample_width = 2
        self.channels = 1

        self.wav_path.parent.mkdir(parents=True, exist_ok=True)
        self._wav = wave.open(str(self.wav_path), "wb")
        self._wav.setnchannels(self.channels)
        self._wav.setsampwidth(self.sample_width)
        self._wav.setframerate(self.sample_rate)
        self._jsonl = open(self.jsonl_path, "a", buffering=1, encoding="utf-8")

        self._lock = threading.RLock()
        self._closed = False
        self._expected_timestamp: Optional[int] = None
        self._last_timestamp: Optional[int] = None
        self._last_sequence: Optional[int] = None
        self._last_wall_time: Optional[float] = None
        self._seen_sequences: set[int] = set()
        self._seen_sequence_order: list[int] = []
        self._max_seen_sequences = 4096
        self._packet_count = 0
        self._written_samples = 0

    @property
    def closed(self) -> bool:
        return self._closed

    def record_packet(self, packet: Any, wall_time: Optional[float] = None, **extra: Any) -> None:
        self.record_encoded_frame(
            encoded_payload=packet.payload,
            sequence_number=packet.sequence_number,
            timestamp=packet.timestamp,
            payload_type=packet.payload_type,
            wall_time=wall_time,
            marker=getattr(packet, "marker", None),
            ssrc=getattr(packet, "ssrc", None),
            **extra,
        )

    def record_encoded_frame(
        self,
        encoded_payload: bytes,
        sequence_number: int,
        timestamp: int,
        payload_type: Optional[CodecInfo] = None,
        wall_time: Optional[float] = None,
        **extra: Any,
    ) -> None:
        if wall_time is None:
            wall_time = time.perf_counter()

        payload_type = payload_type or self.codec
        payload_len = len(encoded_payload or b"")

        with self._lock:
            if self._closed:
                return

            seq = int(sequence_number) & 0xFFFF
            ts = int(timestamp) & 0xFFFFFFFF
            duplicate = seq in self._seen_sequences
            if not duplicate:
                self._seen_sequences.add(seq)
                self._seen_sequence_order.append(seq)
                if len(self._seen_sequence_order) > self._max_seen_sequences:
                    old_seq = self._seen_sequence_order.pop(0)
                    self._seen_sequences.discard(old_seq)

            sequence_delta = None
            timestamp_delta = None
            wall_delta_ms = None
            if self._last_sequence is not None:
                sequence_delta = _signed_delta(seq, self._last_sequence, 16)
            if self._last_timestamp is not None:
                timestamp_delta = _signed_delta(ts, self._last_timestamp, 32)
            if self._last_wall_time is not None:
                wall_delta_ms = (wall_time - self._last_wall_time) * 1000.0

            try:
                decoded = self.decoder.decode(encoded_payload or b"")
            except Exception as exc:
                self._write_jsonl({
                    "direction": self.direction,
                    "event": "decode_error",
                    "wall_time": wall_time,
                    "seq": seq,
                    "timestamp": ts,
                    "payload_type": str(payload_type),
                    "payload_len": payload_len,
                    "error": repr(exc),
                    **extra,
                })
                self._update_last(seq, ts, wall_time)
                return

            decoded_samples = len(decoded) // self.sample_width
            inserted_silence_samples = 0
            late_or_reordered = False
            timestamp_regression = False
            ignored_for_wav = False

            if self._expected_timestamp is None:
                self._expected_timestamp = ts

            timeline_delta = _signed_delta(ts, self._expected_timestamp, 32)

            if timeline_delta > 0:
                inserted_silence_samples = timeline_delta
                self._wav.writeframes(b"\x00\x00" * inserted_silence_samples)
                self._written_samples += inserted_silence_samples
                self._expected_timestamp = ts
            elif timeline_delta < 0:
                late_or_reordered = True
                timestamp_regression = True
                ignored_for_wav = True

            if duplicate:
                ignored_for_wav = True

            if not ignored_for_wav:
                self._wav.writeframes(decoded)
                self._written_samples += decoded_samples
                self._expected_timestamp = (ts + decoded_samples) & 0xFFFFFFFF

            self._packet_count += 1
            self._write_jsonl({
                "direction": self.direction,
                "event": "packet",
                "packet_index": self._packet_count,
                "wall_time": wall_time,
                "seq": seq,
                "timestamp": ts,
                "payload_type": str(payload_type),
                "payload_len": payload_len,
                "decoded_samples": decoded_samples,
                "sequence_delta": sequence_delta,
                "timestamp_delta": timestamp_delta,
                "wall_delta_ms": wall_delta_ms,
                "inserted_silence_samples": inserted_silence_samples,
                "duplicate": duplicate,
                "late_or_reordered": late_or_reordered,
                "timestamp_regression": timestamp_regression,
                "ignored_for_wav": ignored_for_wav,
                "expected_timestamp_after": self._expected_timestamp,
                "written_samples_total": self._written_samples,
                **extra,
            })
            self._update_last(seq, ts, wall_time)

    def _update_last(self, seq: int, ts: int, wall_time: float) -> None:
        self._last_sequence = seq
        self._last_timestamp = ts
        self._last_wall_time = wall_time

    def _write_jsonl(self, event: dict[str, Any]) -> None:
        try:
            self._jsonl.write(json.dumps(event, sort_keys=True, default=str) + "\n")
        except Exception:
            # Recorder must never break RTP processing.
            pass

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                self._write_jsonl({
                    "direction": self.direction,
                    "event": "close",
                    "packet_count": self._packet_count,
                    "written_samples_total": self._written_samples,
                    "duration_seconds": self._written_samples / float(self.sample_rate),
                    "wav_path": str(self.wav_path),
                    "jsonl_path": str(self.jsonl_path),
                })
            finally:
                try:
                    self._jsonl.close()
                finally:
                    self._wav.close()


def create_rtp_recorders(codec: CodecInfo, call_id: Optional[str] = None) -> Tuple[Optional[RTPWavRecorder], Optional[RTPWavRecorder], Optional[Path]]:
    """Create incoming/outgoing recorders if PYSIP_RTP_RECORD is enabled."""
    if not _truthy(os.environ.get("PYSIP_RTP_RECORD")):
        return None, None, None

    root = Path(os.environ.get("PYSIP_RTP_RECORD_DIR", "/tmp/pysip_rtp_recordings"))
    session = f"{time.strftime('%Y%m%d_%H%M%S')}_{_safe_name(call_id)}"
    session_dir = root / session
    incoming = RTPWavRecorder(session_dir / "incoming_rtp.wav", codec, "incoming")
    outgoing = RTPWavRecorder(session_dir / "outgoing_rtp.wav", codec, "outgoing")
    return incoming, outgoing, session_dir
