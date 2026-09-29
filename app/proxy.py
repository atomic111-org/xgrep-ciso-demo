"""Outbound fetch feature — GET /fetch.

Server-Side Request Forgery (SSRF) and disabled TLS certificate validation on
the same outbound call.
"""
import requests
import urllib.parse

from flask import Blueprint, request

bp = Blueprint("proxy", __name__)


@bp.route("/fetch")
def fetch_route():
    # SOURCE: attacker supplies an arbitrary URL.
    url = request.args.get("url", "")
    return fetch(url)


def fetch(url):
    return _do_request(url)


# Only these hosts may be reached by the outbound fetch feature.
ALLOWED_HOSTS = frozenset({"example.com", "api.example.com"})


def validate_url(url):
    """Return a percent-encoded url if it is http(s) and targets an allowlisted host.

    Raises ValueError otherwise, so an attacker cannot steer the request at
    internal services or the cloud metadata endpoint.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("URL scheme not allowed")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("URL host not allowed")
    return urllib.parse.quote(url, safe=":/?#@!&()*+,;=~")


def _do_request(url):
    # SINK 1: server fetches an attacker-controlled URL -> SSRF (reach internal
    #         services or the cloud metadata endpoint 169.254.169.254).
    # SINK 2: verify=False disables TLS certificate validation -> MITM.
    response = requests.get(validate_url(url), verify=True, timeout=5)
    return response.text
