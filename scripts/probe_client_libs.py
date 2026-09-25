#!/usr/bin/env python3
"""Which async HTTP client can send a raw, un-normalised URI path?

Scenario S4's GenericLFI_URIPATH payload only tests anything if the `..`
segments survive to AWS. This decides which library the Week 4 generator is
built on.
"""
import asyncio
import subprocess

BASE = subprocess.run(
    ["terraform", "-chdir=infra/00-core", "output", "-raw", "api_invoke_url"],
    capture_output=True, text=True, check=True).stdout.strip()

HOST = BASE.split("//", 1)[1].split("/", 1)[0]
RAW_TARGET = "/exp/api/../../etc/passwd"   # what must arrive at AWS
EXPECT_MARKER = '"status":"ok"'            # only the Lambda returns this


async def try_aiohttp():
    import aiohttp
    from yarl import URL
    url = URL(f"https://{HOST}{RAW_TARGET}", encoded=True)
    async with aiohttp.ClientSession() as s:
        async with s.get(url) as r:
            body = await r.text()
            return r.status, body


async def try_raw_h11():
    """Last resort: speak HTTP/1.1 over a TLS socket directly."""
    import ssl
    ctx = ssl.create_default_context()
    reader, writer = await asyncio.open_connection(HOST, 443, ssl=ctx, server_hostname=HOST)
    req = (f"GET {RAW_TARGET} HTTP/1.1\r\n"
           f"Host: {HOST}\r\n"
           f"User-Agent: ddos-eval-probe\r\n"
           f"Connection: close\r\n\r\n")
    writer.write(req.encode())
    await writer.drain()
    data = await reader.read()
    writer.close()
    head, _, body = data.partition(b"\r\n\r\n")
    status = int(head.split(b"\r\n", 1)[0].split(b" ")[1])
    return status, body.decode(errors="replace")


async def main():
    print(f"host        : {HOST}")
    print(f"raw target  : {RAW_TARGET}")
    print("             (must arrive un-normalised for S4 to test anything)\n")

    for name, fn in (("aiohttp + yarl(encoded=True)", try_aiohttp),
                     ("raw asyncio TLS socket", try_raw_h11)):
        try:
            status, body = await fn()
            ok = EXPECT_MARKER in body
            verdict = "PATH PRESERVED" if ok else "path rewritten or rejected"
            print(f"  {name:<32} {status}  {verdict}")
        except Exception as e:  # noqa: BLE001
            print(f"  {name:<32} ERROR {type(e).__name__}: {e}")


asyncio.run(main())
