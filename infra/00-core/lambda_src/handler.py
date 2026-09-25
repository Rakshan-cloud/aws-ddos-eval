"""Target of the study. Returns a fixed synthetic response.

Deliberately does nothing: no input parsing, no database, no downstream calls,
no branching on the request. The backend must be a constant so that every
measured difference is attributable to the protection layer in front of it
rather than to the application.

This is also why the scenario S4 payloads are harmless: nothing in this
function reads them, so nothing in it can be exploited by them.
"""

# Fixed ~300-byte body. Response size is a controlled variable - changing it
# would change CloudFront transfer behaviour and invalidate completed runs.
BODY = '{"status":"ok","service":"ddos-eval-target","pad":"' + ("x" * 256) + '"}'


def handler(event, context):
    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
            # Caching is disabled at the CloudFront distribution too (controlled
            # variable). Setting it here as well means a cached response can
            # never silently enter the measurement from either direction.
            "Cache-Control": "no-store",
        },
        "body": BODY,
    }
