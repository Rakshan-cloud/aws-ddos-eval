#!/usr/bin/env python3
"""Task T028 - rate-accurate async HTTP client with per-request recording.

Produces the client-side records that are the primary source for M2
(legitimate-traffic success rate), M3 (error behaviour) and M4 (p95 latency).

Three properties matter more than throughput:

1. RATE ACCURACY. The independent variable is requests per second. If the
   generator drifts, the scenario is not the scenario, and a rate-based rule
   either trips when it should not or fails to trip when it should.

2. PAYLOAD FIDELITY. Every payload must arrive at AWS exactly as written.
   Two separate harness defects have already been caught doing otherwise
   (ADR 0002, ADR 0003), each of which would have produced a silent false
   negative. This module refuses to send a request it cannot verify.

3. HONEST TIMING. Latency is measured around the request only, using a
   monotonic clock, with the connection pool pre-warmed so TLS handshakes do
   not land inside the measurement.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import asdict, dataclass, field
from typing import Iterator

import aiohttp
from yarl import URL

from .payloads import BENIGN_HEADERS, BENIGN_PATH, S4_PAYLOADS


@dataclass
class Record:
    """One request. This schema is the unit of analysis for M2, M3 and M4."""
    t_send: float           # unix epoch, for joining to AWS telemetry
    t_mono_ms: float        # monotonic offset from run start, for ordering
    source: str             # "attacker" or "legit"
    payload: str            # payload class label
    path: str               # URI path AS SENT, not as intended
    status: int | str       # HTTP status, or an error string
    latency_ms: float       # full request, client-observed
    ttfb_ms: float          # time to first byte
    bytes_: int = 0
    aws_request_id: str = ""    # x-amzn-requestid, joins to API Gateway logs
    cf_request_id: str = ""     # x-amz-cf-id, joins to CloudFront logs
    waf_action: str = ""        # present when AWS WAF acts on the request
    phase: str = ""


def s4_rotation() -> Iterator[tuple[str, str, dict]]:
    """Cycle the S4 payload classes round-robin, indefinitely.

    Round-robin rather than random: every class gets an equal share of the
    run, so the per-rule breakdown has comparable sample sizes. A random
    choice would leave some classes thinly sampled by chance.
    """
    while True:
        for label, path, headers, _rule, _lbl in S4_PAYLOADS:
            yield label, path, headers


class Generator:
    def __init__(self, base_url: str, source: str, *, verify_payloads: bool = True):
        self.base = base_url.rstrip("/")
        self.source = source
        self.verify_payloads = verify_payloads
        self.records: list[Record] = []
        self._s4 = s4_rotation()

    def _build(self, payload_kind: str):
        """Return (label, url, headers, skip_auto_headers) for the next request."""
        if payload_kind == "benign":
            label, path, headers = "benign", BENIGN_PATH, dict(BENIGN_HEADERS)
        elif payload_kind == "s4_rotating":
            label, path, headers = next(self._s4)
            headers = dict(headers)
        else:
            raise ValueError(f"unknown payload kind: {payload_kind}")

        # A header mapped to None means "omit entirely". Leaving the key out of
        # the dict is NOT sufficient -- aiohttp substitutes its own User-Agent,
        # which silently defeats the NoUserAgent_HEADER rule (ADR 0003).
        skip = [k for k, v in headers.items() if v is None]
        headers = {k: v for k, v in headers.items() if v is not None}
        headers.setdefault("User-Agent", "ddos-eval-client/1.0")
        for k in skip:
            headers.pop(k, None)

        # encoded=True sends the path and query verbatim. Without it the client
        # resolves `..` segments and re-encodes the query string, and the
        # payload never reaches AWS as written (ADR 0002).
        url = URL(self.base + path, encoded=True)
        return label, url, headers, skip

    def verify_delivery(self) -> list[str]:
        """Assert every payload survives URL construction unaltered.

        Called once before a run starts. Returns a list of problems; an empty
        list means every payload will be transmitted as written. The runner
        refuses to start if this is non-empty, because a rewritten payload
        produces a result that looks clean and is wrong.
        """
        problems = []
        for label, path, headers, _rule, _lbl in S4_PAYLOADS:
            url = URL(self.base + path, encoded=True)
            intended = self.base + path
            if str(url) != intended:
                problems.append(f"{label}: built {url!s}, intended {intended}")
        return problems

    async def _once(self, session, payload_kind, phase, t0_mono, t0_wall):
        label, url, headers, skip = self._build(payload_kind)
        t_send = t0_wall + (time.monotonic() - t0_mono)
        start = time.perf_counter()
        ttfb = 0.0
        try:
            async with session.get(url, headers=headers, skip_auto_headers=skip,
                                   timeout=aiohttp.ClientTimeout(total=20)) as r:
                ttfb = (time.perf_counter() - start) * 1000
                body = await r.read()
                rec = Record(
                    t_send=t_send,
                    t_mono_ms=(time.monotonic() - t0_mono) * 1000,
                    source=self.source, payload=label, path=str(url.raw_path),
                    status=r.status,
                    latency_ms=(time.perf_counter() - start) * 1000,
                    ttfb_ms=ttfb, bytes_=len(body),
                    aws_request_id=r.headers.get("x-amzn-requestid", ""),
                    cf_request_id=r.headers.get("x-amz-cf-id", ""),
                    waf_action=r.headers.get("x-amzn-waf-action", ""),
                    phase=phase,
                )
        except Exception as e:  # noqa: BLE001
            rec = Record(
                t_send=t_send, t_mono_ms=(time.monotonic() - t0_mono) * 1000,
                source=self.source, payload=label, path=str(url.raw_path),
                status=f"ERR {type(e).__name__}",
                latency_ms=(time.perf_counter() - start) * 1000,
                ttfb_ms=ttfb, phase=phase,
            )
        self.records.append(rec)

    async def run_phase(self, session, rate, duration, payload_kind, phase,
                        t0_mono, t0_wall):
        """Send at `rate` req/s for `duration` seconds.

        Requests are DISPATCHED on schedule and awaited concurrently. A
        sequential loop would let each request's own latency push the next one
        later, so at 10 req/s with 170 ms responses the achieved rate would sag
        well below target and the scenario would silently become a different
        scenario.

        The schedule is absolute (`next_at += interval`) rather than
        `sleep(interval)`, so per-iteration overhead cannot accumulate into
        drift over a 600-second window.
        """
        if rate <= 0:
            await asyncio.sleep(duration)
            return

        interval = 1.0 / rate
        end = time.monotonic() + duration
        next_at = time.monotonic()
        pending: set[asyncio.Task] = set()

        while time.monotonic() < end:
            next_at += interval
            task = asyncio.create_task(
                self._once(session, payload_kind, phase, t0_mono, t0_wall))
            pending.add(task)
            task.add_done_callback(pending.discard)

            sleep = next_at - time.monotonic()
            if sleep > 0:
                await asyncio.sleep(sleep)
            # If sleep <= 0 the generator is behind schedule. It does not try
            # to catch up by firing faster, because that would breach the rate
            # ceiling asserted in scenarios.yaml. The shortfall is visible in
            # the achieved-rate figure the runner reports.

        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    async def warmup(self, session, seconds):
        """Fill the connection pool and absorb the Lambda cold start.

        Warm-up records are discarded. TLS handshake and cold-start latency are
        real, but they are not what the protection layers are being compared
        on, and at ~1000 ms they would dominate a p95 built from 600 samples.
        """
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            try:
                async with session.get(URL(self.base + BENIGN_PATH, encoded=True),
                                       headers=dict(BENIGN_HEADERS),
                                       timeout=aiohttp.ClientTimeout(total=20)) as r:
                    await r.read()
            except Exception:  # noqa: BLE001, S110
                pass
            await asyncio.sleep(1.0)

    def to_dicts(self):
        return [{**asdict(r), "bytes": r.bytes_} for r in self.records]
