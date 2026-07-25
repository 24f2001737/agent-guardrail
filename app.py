import os
import ipaddress
import socket
from urllib.parse import urlparse, unquote

import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# ============================================================
# CONFIGURATION
# ============================================================

SANDBOX_ROOT = "/srv/agent-redteam/sandbox-c2950d8cd1"

ALLOWED_HOSTS = {
    "example.com",
    "www.iana.org",
}


# ============================================================
# FILE SECURITY
# ============================================================

def safe_file_path(path):
    """
    Resolve a requested path and ensure it remains inside
    the sandbox directory.
    """

    if not isinstance(path, str) or not path:
        return None

    try:
        # Decode URL-style encoding.
        # This catches things such as %2e%2e.
        decoded = unquote(path)

        # Resolve the path against the sandbox root.
        root = os.path.realpath(SANDBOX_ROOT)

        # If the supplied path is absolute, use it directly.
        # Otherwise, interpret it relative to the sandbox.
        if os.path.isabs(decoded):
            candidate = os.path.realpath(decoded)
        else:
            candidate = os.path.realpath(
                os.path.join(root, decoded)
            )

        # Must be the sandbox itself or a child of it.
        if os.path.commonpath([root, candidate]) != root:
            return None

        return candidate

    except (ValueError, OSError):
        return None


def read_safe_file(path):
    resolved = safe_file_path(path)

    if resolved is None:
        return None, "Path is outside the permitted sandbox."

    try:
        if not os.path.isfile(resolved):
            return None, "Requested file does not exist."

        with open(
            resolved,
            "r",
            encoding="utf-8",
            errors="replace"
        ) as f:
            return f.read(), None

    except OSError as e:
        return None, f"Unable to read file: {e}"


# ============================================================
# NETWORK SECURITY
# ============================================================

def is_private_or_reserved_ip(hostname):
    """
    Resolve the hostname and reject private, loopback,
    link-local, multicast, unspecified, and reserved addresses.
    """

    try:
        addresses = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM
        )

        for item in addresses:
            ip = item[4][0]

            try:
                addr = ipaddress.ip_address(ip)

                if (
                    addr.is_private
                    or addr.is_loopback
                    or addr.is_link_local
                    or addr.is_multicast
                    or addr.is_reserved
                    or addr.is_unspecified
                ):
                    return True

            except ValueError:
                return True

        return False

    except socket.gaierror:
        return True


def validate_url(url):
    """
    Validate URL against the strict network policy.
    """

    if not isinstance(url, str) or not url:
        return False, "Invalid URL."

    try:
        parsed = urlparse(url)

        # HTTPS only.
        if parsed.scheme.lower() != "https":
            return False, "Only HTTPS URLs are allowed."

        # A hostname must exist.
        hostname = parsed.hostname

        if not hostname:
            return False, "URL has no hostname."

        hostname = hostname.lower().rstrip(".")

        # Reject userinfo such as:
        # https://example.com@evil.com
        if parsed.username is not None or parsed.password is not None:
            return False, "URLs containing userinfo are blocked."

        # Exact host match.
        if hostname not in ALLOWED_HOSTS:
            return False, "Hostname is not on the allowlist."

        # Resolve the hostname and make sure it doesn't resolve
        # to a private/internal address.
        if is_private_or_reserved_ip(hostname):
            return False, "Hostname resolves to a private or reserved address."

        return True, None

    except Exception:
        return False, "Malformed URL."


def fetch_safe_url(url):
    valid, reason = validate_url(url)

    if not valid:
        return None, reason

    try:
        # Disable automatic redirects.
        # This is critical because an allowed URL could otherwise
        # redirect to an internal/private destination.
        response = requests.get(
            url,
            timeout=8,
            allow_redirects=False,
            headers={
                "User-Agent": "Agent-Guardrail/1.0"
            }
        )

        # If the allowed host tries to redirect somewhere else,
        # do not follow it.
        if 300 <= response.status_code < 400:
            return None, "Redirects are blocked."

        return response.text, None

    except requests.RequestException as e:
        return None, f"Network request failed: {e}"


# ============================================================
# MAIN GUARDRAIL
# ============================================================

@app.route("/", methods=["POST"])
def guardrail():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "action": "block",
            "reason": "Request body must be valid JSON.",
            "result": ""
        }), 400

    tool = data.get("tool")
    arguments = data.get("arguments")

    if not isinstance(arguments, dict):
        return jsonify({
            "action": "block",
            "reason": "Arguments must be a JSON object.",
            "result": ""
        }), 400

    # ========================================================
    # READ FILE
    # ========================================================

    if tool == "read_file":

        path = arguments.get("path")

        if not isinstance(path, str):
            return jsonify({
                "action": "block",
                "reason": "A valid path is required.",
                "result": ""
            })

        content, error = read_safe_file(path)

        if error:
            return jsonify({
                "action": "block",
                "reason": error,
                "result": ""
            })

        return jsonify({
            "action": "allow",
            "reason": "Path is within the permitted sandbox.",
            "result": content
        })

    # ========================================================
    # FETCH URL
    # ========================================================

    if tool == "fetch_url":

        url = arguments.get("url")

        if not isinstance(url, str):
            return jsonify({
                "action": "block",
                "reason": "A valid URL is required.",
                "result": ""
            })

        content, error = fetch_safe_url(url)

        if error:
            return jsonify({
                "action": "block",
                "reason": error,
                "result": ""
            })

        return jsonify({
            "action": "allow",
            "reason": "URL host is on the exact HTTPS allowlist.",
            "result": content
        })

    # ========================================================
    # UNKNOWN TOOL
    # ========================================================

    return jsonify({
        "action": "block",
        "reason": "Unknown tool.",
        "result": ""
    })


@app.route("/", methods=["GET"])
def health():
    return jsonify({
        "status": "ok"
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000))
    )
