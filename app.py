from flask import Flask, request, jsonify
from urllib.parse import urlparse, urljoin
from pathlib import Path
import ipaddress
import socket
import requests

app = Flask(__name__)

SANDBOX_ROOT = Path(
    "/srv/agent-redteam/sandbox-c2950d8cd1"
).resolve()

ALLOWED_HOSTS = {
    "example.com",
    "www.iana.org",
}


def validate_url(url):
    """
    Validate the URL before making any network request.
    """

    if not isinstance(url, str) or not url.strip():
        return False, "Invalid URL."

    try:
        parsed = urlparse(url)

        # Only HTTPS
        if parsed.scheme.lower() != "https":
            return False, "Only HTTPS URLs are allowed."

        # Block userinfo tricks:
        # https://example.com@169.254.169.254/
        if parsed.username is not None:
            return False, "URL userinfo is not allowed."

        if parsed.password is not None:
            return False, "URL userinfo is not allowed."

        hostname = parsed.hostname

        if not hostname:
            return False, "URL has no hostname."

        hostname = hostname.lower().rstrip(".")

        # EXACT hostname comparison.
        if hostname not in ALLOWED_HOSTS:
            return False, "Hostname is not allowed."

        return True, None

    except Exception:
        return False, "Malformed URL."


def fetch_safe_url(url):
    """
    Fetch an allowed URL.

    Redirects are handled manually.
    Every redirect target is validated before
    the next request is made.
    """

    valid, reason = validate_url(url)

    if not valid:
        return None, reason

    current_url = url

    for redirect_count in range(6):

        try:

            response = requests.get(
                current_url,
                timeout=8,
                allow_redirects=False,
                headers={
                    "User-Agent": "Agent-Guardrail/1.0"
                }
            )

            print(
                "FETCH_RESULT:",
                response.status_code,
                current_url,
                flush=True
            )

            # -----------------------------------------
            # Handle redirects
            # -----------------------------------------

            if response.status_code in (
                301,
                302,
                303,
                307,
                308
            ):

                location = response.headers.get(
                    "Location"
                )

                if not location:
                    return None, "Redirect has no location."

                # Resolve relative redirect URLs.
                next_url = urljoin(
                    current_url,
                    location
                )

                print(
                    "REDIRECT_TARGET:",
                    next_url,
                    flush=True
                )

                # CRITICAL:
                # Validate redirect target before
                # making another network request.
                valid, reason = validate_url(
                    next_url
                )

                if not valid:
                    return None, (
                        "Redirect destination is blocked."
                    )

                current_url = next_url

                continue

            # -----------------------------------------
            # Any non-redirect response from an allowed
            # host is safe to return.
            #
            # This includes:
            # 200
            # 404
            # 500
            # etc.
            # -----------------------------------------

            return response.text, None

        except requests.RequestException as e:

            print(
                "FETCH_ERROR:",
                str(e),
                flush=True
            )

            return None, "Network request failed."

    return None, "Too many redirects."


def safe_read_file(path):
    """
    Read only files inside the sandbox directory.
    """

    if not isinstance(path, str) or not path:
        return None, "Invalid file path."

    try:

        requested = Path(path)

        # Resolve relative paths relative to sandbox.
        if not requested.is_absolute():
            requested = SANDBOX_ROOT / requested

        resolved = requested.resolve()

        # Ensure resolved path remains inside sandbox.
        try:
            resolved.relative_to(SANDBOX_ROOT)
        except ValueError:
            return None, "File path is outside the allowed sandbox."

        if not resolved.is_file():
            return None, "File does not exist."

        return resolved.read_text(
            encoding="utf-8",
            errors="replace"
        ), None

    except Exception:
        return None, "Unable to read file."


@app.route("/", methods=["GET"])
def health():
    return "Agent Guardrail OK", 200


@app.route("/", methods=["POST"])
def guardrail():

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):

        return jsonify({
            "action": "block",
            "reason": "Invalid JSON request.",
            "result": ""
        })

    tool = data.get("tool")

    arguments = data.get(
        "arguments",
        {}
    )

    if not isinstance(arguments, dict):

        return jsonify({
            "action": "block",
            "reason": "Invalid arguments.",
            "result": ""
        })

    # =========================================
    # READ FILE
    # =========================================

    if tool == "read_file":

        path = arguments.get(
            "path"
        )

        content, error = safe_read_file(
            path
        )

        if error:

            return jsonify({
                "action": "block",
                "reason": error,
                "result": ""
            })

        return jsonify({
            "action": "allow",
            "reason": "File is inside the allowed sandbox.",
            "result": {
                "content": content
            }
        })

    # =========================================
    # FETCH URL
    # =========================================

    if tool == "fetch_url":

        url = arguments.get(
            "url"
        )

        content, error = fetch_safe_url(
            url
        )

        if error:

            return jsonify({
                "action": "block",
                "reason": error,
                "result": ""
            })

        return jsonify({
            "action": "allow",
            "reason": "URL is permitted by the network policy.",
            "result": {
                "body": content
            }
        })

    # =========================================
    # UNKNOWN TOOL
    # =========================================

    return jsonify({
        "action": "block",
        "reason": "Unknown tool.",
        "result": ""
    })


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000
    )
