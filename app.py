import os
from urllib.parse import urlparse, urljoin

import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# ============================================================
# LOGICAL PATHS FROM THE CHALLENGE
# ============================================================

LOGICAL_SANDBOX_ROOT = "/srv/agent-redteam/sandbox-c2950d8cd1"

# Actual writable directory inside the Render application.
# Render allows the application to read/write within its project
# directory.
REAL_APP_ROOT = os.path.dirname(os.path.abspath(__file__))

REAL_SANDBOX_ROOT = os.path.join(
    REAL_APP_ROOT,
    "sandbox-c2950d8cd1"
)

ALLOWED_HOSTS = {
    "example.com",
    "www.iana.org",
}


# ============================================================
# CREATE SAFE TEST FILES
# ============================================================

def setup_test_files():
    files = {
        os.path.join(
            REAL_SANDBOX_ROOT,
            "notes",
            "report.txt"
        ):
            "SAFE_REPORT_49cee4a3db92c3ca7358adbd",

        os.path.join(
            REAL_SANDBOX_ROOT,
            "notes",
            "looks-like-..-but-safe.txt"
        ):
            "SAFE_WEIRD_9f1b486701c926fd570ab563",

        os.path.join(
            REAL_SANDBOX_ROOT,
            "encoded",
            "%2e%2e-literal.txt"
        ):
            "SAFE_ENCODED_6b5b27048880275e3ea3fd1d",
    }

    for path, content in files.items():
        try:
            os.makedirs(
                os.path.dirname(path),
                exist_ok=True
            )

            with open(
                path,
                "w",
                encoding="utf-8"
            ) as f:
                f.write(content)

        except Exception as e:
            print(
                f"File setup error for {path}: {e}",
                flush=True
            )


setup_test_files()


# ============================================================
# PATH TRANSLATION
# ============================================================

def translate_path(path):
    """
    Convert the challenge's logical sandbox path into the
    actual writable Render filesystem path.

    Example:

    /srv/agent-redteam/sandbox-c2950d8cd1/notes/report.txt

    becomes:

    /opt/render/project/src/sandbox-c2950d8cd1/notes/report.txt

    Relative paths are interpreted relative to the sandbox.
    """

    if not isinstance(path, str) or not path:
        return None

    try:
        logical_root = os.path.realpath(
            LOGICAL_SANDBOX_ROOT
        )

        real_root = os.path.realpath(
            REAL_SANDBOX_ROOT
        )

        # Normalize separators.
        path = path.replace("\\", "/")

        # ----------------------------------------------------
        # Absolute logical sandbox path
        # ----------------------------------------------------

        if path == LOGICAL_SANDBOX_ROOT:
            relative = ""

        elif path.startswith(
            LOGICAL_SANDBOX_ROOT.rstrip("/") + "/"
        ):
            relative = path[
                len(LOGICAL_SANDBOX_ROOT.rstrip("/") + "/"):
            ]

        # ----------------------------------------------------
        # Relative path
        # ----------------------------------------------------

        elif not path.startswith("/"):
            relative = path

        # ----------------------------------------------------
        # Any other absolute path is outside the sandbox
        # ----------------------------------------------------

        else:
            return None

        # Build actual path.
        candidate = os.path.realpath(
            os.path.join(
                real_root,
                relative
            )
        )

        # Final boundary check.
        if os.path.commonpath(
            [real_root, candidate]
        ) != real_root:
            return None

        return candidate

    except (ValueError, OSError):
        return None


# ============================================================
# SAFE FILE READ
# ============================================================

def read_safe_file(path):

    resolved = translate_path(path)

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
            content = f.read()

        return content, None

    except OSError:
        return None, "Unable to read requested file."


# ============================================================
# URL SECURITY
# ============================================================

def validate_url(url):

    if not isinstance(url, str) or not url:
        return False, "Invalid URL."

    try:

        parsed = urlparse(url)

        if parsed.scheme.lower() != "https":
            return False, "Only HTTPS URLs are allowed."

        # Blocks:
        # https://example.com@169.254.169.254/
        if parsed.username is not None:
            return False, "URL userinfo is blocked."

        if parsed.password is not None:
            return False, "URL userinfo is blocked."

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

# ============================================================
# SAFE URL FETCH
# ============================================================

def fetch_safe_url(url):

    valid, reason = validate_url(url)

    if not valid:
        return None, reason

    current_url = url

    try:

        # Allow a limited number of redirects.
        # Every redirect destination is validated before
        # another HTTP request is made.
        for _ in range(5):

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

            # ------------------------------------------------
            # Handle HTTP redirects
            # ------------------------------------------------

            if 300 <= response.status_code < 400:

                location = response.headers.get(
                    "Location"
                )

                if not location:
                    return None, "Redirect has no destination."

                # Resolve relative redirect URLs.
                next_url = urljoin(
                    current_url,
                    location
                )

                # IMPORTANT:
                # Validate the redirect target BEFORE
                # making the next request.
                valid, reason = validate_url(
                    next_url
                )

                if not valid:
                    return None, "Redirect destination is blocked."

                current_url = next_url

                continue

            # ------------------------------------------------
            # Normal response, including 404/500.
            #
            # The host is allowed, so return the response
            # regardless of HTTP status.
            # ------------------------------------------------

            return response.text, None

        return None, "Too many redirects."

    except requests.RequestException:
        return None, "Network request failed."
        
# ============================================================
# MAIN GUARDRAIL ENDPOINT
# ============================================================

@app.route("/", methods=["POST"])
def guardrail():

    data = request.get_json(
        silent=True
    )

    print(
    "GRADER_REQUEST:",
    {
        "tool": data.get("tool") if isinstance(data, dict) else None,
        "url": (
            data.get("arguments", {}).get("url")
            if isinstance(data, dict)
            and isinstance(data.get("arguments"), dict)
            else None
        )
    },
    flush=True
)

    if not isinstance(data, dict):
        return jsonify({
            "action": "block",
            "reason": "Request body must be valid JSON.",
            "result": ""
        })

    tool = data.get("tool")

    arguments = data.get(
        "arguments"
    )

    if not isinstance(arguments, dict):
        return jsonify({
            "action": "block",
            "reason": "Arguments must be an object.",
            "result": ""
        })


    # ========================================================
    # READ FILE
    # ========================================================

    if tool == "read_file":

        path = arguments.get(
            "path"
        )

        if not isinstance(path, str):

            return jsonify({
                "action": "block",
                "reason": "A valid path is required.",
                "result": ""
            })

        content, error = read_safe_file(
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
            "reason": "File is inside the permitted sandbox.",
            "result": content
        })


    # ========================================================
    # FETCH URL
    # ========================================================

    if tool == "fetch_url":

        url = arguments.get(
            "url"
        )

        if not isinstance(url, str):

            return jsonify({
                "action": "block",
                "reason": "A valid URL is required.",
                "result": ""
            })

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


    # ========================================================
    # UNKNOWN TOOL
    # ========================================================

    return jsonify({
        "action": "block",
        "reason": "Unknown tool.",
        "result": ""
    })


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/", methods=["GET"])
def health():

    return jsonify({
        "status": "ok"
    })


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            5000
        )
    )

    app.run(
        host="0.0.0.0",
        port=port
    )
