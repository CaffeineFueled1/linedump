from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import PlainTextResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import bleach
import secrets
import string
import os
from pathlib import Path
import hashlib
from typing import Optional
import json
from datetime import datetime
import sys


BASEURL = os.getenv('BASEURL', 'http://127.0.0.1:8000')
DESCRIPTION = os.getenv('DESCRIPTION', 'CLI-only pastebin powered by linedump.com')
MAX_FILE_SIZE_MB = int(os.getenv('MAX_FILE_SIZE_MB', '50'))
RATE_LIMIT = os.getenv('RATE_LIMIT', '50/hour')
URL_PATH_LENGTH = int(os.getenv('URL_PATH_LENGTH', '6'))
UPLOAD_TOKENS = [t.strip() for t in os.getenv('UPLOAD_TOKENS', '').split(',') if t.strip()] if os.getenv('UPLOAD_TOKENS') else []
LOGGING_ENABLED = os.getenv('LOGGING_ENABLED', 'false').lower() in ['true', '1', 'yes']
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
LOG_FILE = 'logs/linedump.log'

# Create logs directory and log file if logging is enabled
if LOGGING_ENABLED:
    Path('logs').mkdir(exist_ok=True)
    Path(LOG_FILE).touch(exist_ok=True)


def log(level: str, event: str, **kwargs):
    """Simple structured logging function"""
    # Skip if logging is disabled
    if not LOGGING_ENABLED:
        return

    # Skip logs based on level
    if LOG_LEVEL == 'ERROR' and level in ['INFO', 'WARNING']:
        return
    if LOG_LEVEL == 'WARNING' and level == 'INFO':
        return

    log_entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "level": level,
        "event": event,
        **kwargs
    }

    log_line = json.dumps(log_entry)

    # Write to file
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(log_line + '\n')
    except:
        pass  # Fail silently if logging fails

    # Write to stdout
    print(log_line, file=sys.stdout)


def get_real_ip(request: Request) -> str:
    """Get real client IP for rate limiting and logging (supports reverse proxy)"""
    # Check X-Real-IP header first (set by reverse proxy)
    x_real_ip = request.headers.get("X-Real-IP")
    if x_real_ip:
        return x_real_ip.strip()
    # Fallback to direct connection IP
    return request.client.host

limiter = Limiter(key_func=get_real_ip)
app = FastAPI(title="linedump", version="1.0.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.exception_handler(RateLimitExceeded)
async def log_rate_limit(request: Request, exc: RateLimitExceeded):
    """Custom handler to log rate limit violations"""
    log("WARNING", "rate_limit_exceeded",
        client_ip=get_real_ip(request),
        user_agent=request.headers.get("User-Agent", "unknown"),
        endpoint=request.url.path)
    return await _rate_limit_exceeded_handler(request, exc)


# Log startup
log("INFO", "application_started",
    base_url=BASEURL,
    max_file_size_mb=MAX_FILE_SIZE_MB,
    auth_enabled=bool(UPLOAD_TOKENS))


UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

MAX_FILE_SIZE = MAX_FILE_SIZE_MB * 1024 * 1024  # Convert MB to bytes

def generate_random_path(length: int = None) -> str:
    if length is None:
        length = URL_PATH_LENGTH
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def generate_deletion_token() -> str:
    """Generate a secure deletion token"""
    return secrets.token_urlsafe(32)


def validate_paste_id(paste_id: str) -> bool:
    """Validate paste ID to prevent path traversal and other attacks"""
    # Must be alphanumeric only
    if not paste_id.isalnum():
        return False
    # Reasonable length check (prevent extremely long IDs)
    if len(paste_id) > 64:
        return False
    # Must not be empty
    if len(paste_id) == 0:
        return False
    return True


def save_metadata(paste_id: str, deletion_token: str, client_ip: str) -> None:
    """Save paste metadata to JSON file"""
    # Validate paste_id before file operations
    if not validate_paste_id(paste_id):
        raise ValueError("Invalid paste ID")

    meta_path = UPLOAD_DIR / f"{paste_id}.meta"

    # Ensure resolved path is within UPLOAD_DIR (prevent path traversal)
    if not str(meta_path.resolve()).startswith(str(UPLOAD_DIR.resolve())):
        raise ValueError("Invalid paste ID: path traversal detected")

    metadata = {
        "deletion_token": deletion_token,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "client_ip": client_ip
    }
    with open(meta_path, 'w') as f:
        json.dump(metadata, f)


def load_metadata(paste_id: str) -> Optional[dict]:
    """Load paste metadata from JSON file"""
    # Validate paste_id before file operations
    if not validate_paste_id(paste_id):
        return None

    meta_path = UPLOAD_DIR / f"{paste_id}.meta"

    # Ensure resolved path is within UPLOAD_DIR (prevent path traversal)
    if not str(meta_path.resolve()).startswith(str(UPLOAD_DIR.resolve())):
        return None

    if not meta_path.exists():
        return None
    try:
        with open(meta_path, 'r') as f:
            return json.load(f)
    except:
        return None


def delete_paste(paste_id: str) -> bool:
    """Delete paste and its metadata"""
    # Validate paste_id before file operations
    if not validate_paste_id(paste_id):
        return False

    paste_path = UPLOAD_DIR / paste_id
    meta_path = UPLOAD_DIR / f"{paste_id}.meta"

    # Ensure resolved paths are within UPLOAD_DIR (prevent path traversal)
    if not str(paste_path.resolve()).startswith(str(UPLOAD_DIR.resolve())):
        return False
    if not str(meta_path.resolve()).startswith(str(UPLOAD_DIR.resolve())):
        return False

    deleted = False
    if paste_path.exists():
        paste_path.unlink()
        deleted = True
    if meta_path.exists():
        meta_path.unlink()

    return deleted


def validate_upload_token(request: Request) -> bool:
    """Validate upload token if authentication is enabled"""
    if not UPLOAD_TOKENS:
        # No tokens configured, authentication is disabled
        return True

    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        log("WARNING", "auth_failed",
            client_ip=get_real_ip(request),
            user_agent=request.headers.get("User-Agent", "unknown"),
            reason="missing_bearer")
        raise HTTPException(
            status_code=401,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Bearer"}
        )

    token = auth[7:]  # Remove "Bearer " prefix

    # Use constant-time comparison to prevent timing attacks
    if not any(secrets.compare_digest(token, valid_token) for valid_token in UPLOAD_TOKENS):
        log("WARNING", "auth_failed",
            client_ip=get_real_ip(request),
            user_agent=request.headers.get("User-Agent", "unknown"),
            reason="invalid_token")
        raise HTTPException(
            status_code=401,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Bearer"}
        )

    return True


def validate_content(content: str) -> bool:
    """Basic validation for content size and encoding"""
    if len(content) > MAX_FILE_SIZE:
        return False
    
    # Check for null bytes (file system attacks)
    if '\x00' in content:
        return False
    
    try:
        # Ensure it's valid UTF-8
        content.encode('utf-8')
        return True
    except UnicodeEncodeError:
        return False

@app.post("/", response_class=PlainTextResponse)
@limiter.limit(RATE_LIMIT)
async def upload_text(request: Request, authorized: bool = Depends(validate_upload_token)):

    client_ip = get_real_ip(request)
    user_agent = request.headers.get("User-Agent", "unknown")
    body = await request.body()
    content = body.decode('utf-8', errors='ignore')

    if not validate_content(content):
        log("WARNING", "upload_failed",
            client_ip=client_ip,
            user_agent=user_agent,
            reason="invalid_content",
            size_bytes=len(content))
        raise HTTPException(status_code=400, detail="Invalid content")

    if not content.strip():
        log("WARNING", "upload_failed",
            client_ip=client_ip,
            user_agent=user_agent,
            reason="empty_content")
        raise HTTPException(status_code=400, detail="Empty content")

    random_path = generate_random_path()
    while (UPLOAD_DIR / random_path).exists():
        random_path = generate_random_path()

    file_path = UPLOAD_DIR / random_path

    try:
        # Generate deletion token
        deletion_token = generate_deletion_token()

        # Save paste content
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)

        # Save metadata with deletion token
        save_metadata(random_path, deletion_token, client_ip)

        log("INFO", "paste_created",
            paste_id=random_path,
            client_ip=client_ip,
            user_agent=user_agent,
            size_bytes=len(content))

        # Return URL and deletion token
        return f"{BASEURL}/{random_path}\nDelete with HTTP POST: {BASEURL}/{random_path}?token={deletion_token}\n"

    except Exception as e:
        log("ERROR", "upload_failed",
            paste_id=random_path,
            client_ip=client_ip,
            user_agent=user_agent,
            error=str(e))
        raise HTTPException(status_code=500, detail="Failed to save file")

@app.get("/{paste_id}", response_class=PlainTextResponse)
async def get_file(paste_id: str, request: Request, token: Optional[str] = None):
    """Get paste content or delete if token is provided"""
    if not paste_id.isalnum():
        raise HTTPException(status_code=404, detail="Paste not found")

    file_location = UPLOAD_DIR / paste_id

    if not file_location.exists() or not file_location.is_file():
        raise HTTPException(status_code=404, detail="Paste not found")

    try:
        with open(file_location, 'r', encoding='utf-8') as f:
            content = f.read()

        return content
    except Exception as e:
        log("ERROR", "download_failed",
            paste_id=paste_id,
            error=str(e))
        raise HTTPException(status_code=500, detail="Failed to read file")


@app.post("/{paste_id}", response_class=PlainTextResponse)
async def delete_paste_endpoint(paste_id: str, request: Request, token: Optional[str] = None):
    """Delete a paste using its deletion token"""
    client_ip = get_real_ip(request)
    user_agent = request.headers.get("User-Agent", "unknown")

    # Validate paste_id format
    if not paste_id.isalnum():
        raise HTTPException(status_code=404, detail="Paste not found")

    # Check if token is provided (query param or header)
    deletion_token = token or request.headers.get("X-Delete-Token")
    if not deletion_token:
        log("WARNING", "deletion_failed",
            paste_id=paste_id,
            client_ip=client_ip,
            user_agent=user_agent,
            reason="missing_token")
        raise HTTPException(status_code=404, detail="Not found")

    # Validate token length (prevent abuse with extremely long tokens)
    if len(deletion_token) > 128:
        log("WARNING", "deletion_failed",
            paste_id=paste_id,
            client_ip=client_ip,
            user_agent=user_agent,
            reason="invalid_token_length")
        raise HTTPException(status_code=403, detail="Deletion failed")

    # Load metadata
    metadata = load_metadata(paste_id)
    if not metadata:
        log("WARNING", "deletion_failed",
            paste_id=paste_id,
            client_ip=client_ip,
            user_agent=user_agent,
            reason="metadata_not_found")
        raise HTTPException(status_code=404, detail="Deletion failed")

    # Verify deletion token using constant-time comparison
    if not secrets.compare_digest(deletion_token, metadata.get("deletion_token", "")):
        log("WARNING", "deletion_failed",
            paste_id=paste_id,
            client_ip=client_ip,
            user_agent=user_agent,
            reason="invalid_token")
        raise HTTPException(status_code=403, detail="Deletion failed")

    # Delete the paste and metadata
    if delete_paste(paste_id):
        log("INFO", "paste_deleted",
            paste_id=paste_id,
            client_ip=client_ip,
            user_agent=user_agent,
            deletion_method="user_requested")
        return "Paste deleted successfully\n"
    else:
        log("ERROR", "deletion_failed",
            paste_id=paste_id,
            client_ip=client_ip,
            user_agent=user_agent,
            reason="file_not_found")
        raise HTTPException(status_code=500, detail="Failed to delete paste")


@app.get("/", response_class=PlainTextResponse)
async def root():
    # Build authentication notice and examples if tokens are configured
    auth_notice = "\n- Authentication: not required"
    auth_section = ""
    auth_header_curl = ""
    auth_header_wget = ""
    auth_header_ps = ""

    if UPLOAD_TOKENS:
        auth_notice = "\n- Authentication: REQUIRED (Bearer token)"
        auth_header_curl = '-H "Authorization: Bearer $LINEDUMP_TOKEN" '
        auth_header_wget = '--header="Authorization: Bearer $LINEDUMP_TOKEN" '
        auth_header_ps = ' -Headers @{"Authorization"="Bearer $env:LINEDUMP_TOKEN"}'
        auth_section = f"""

████ Authentication Examples ████

When authentication is enabled, include Bearer token in Authorization header:

Set token as environment variable (recommended):
export LINEDUMP_TOKEN="your-token-here"

    █ curl:
curl -H "Authorization: Bearer $LINEDUMP_TOKEN" -X POST -d "Cheers" {BASEURL}/

    █ wget:
wget --header="Authorization: Bearer $LINEDUMP_TOKEN" --post-data="Cheers" -O- {BASEURL}/

    █ Powershell:
$env:LINEDUMP_TOKEN="your-token-here"
Invoke-RestMethod -Uri "{BASEURL}/" -Headers @{{"Authorization"="Bearer $env:LINEDUMP_TOKEN"}} -Method Post -Body "Cheers"
"""

    return f"""LD {BASEURL}

 ████ General ████

{DESCRIPTION}

- File limit: {MAX_FILE_SIZE_MB} MB
- Rate limit: {RATE_LIMIT}
- text-only
- no server-side encryption, consider content public or use client-side encryption{auth_notice}
{auth_section}

████ Usage ████


    █ Upload curl:

curl {auth_header_curl}-X POST -d "Cheers" {BASEURL}/                  # string
curl {auth_header_curl}-X POST {BASEURL} --data-binary @- < file.txt   # file
ip -br a | curl {auth_header_curl}-X POST {BASEURL} --data-binary @-   # command output


    █ Upload wget:

echo "Cheers" | wget {auth_header_wget}--post-data=@- -O- {BASEURL}/   # string
wget {auth_header_wget}--post-file=file.txt -O- {BASEURL}/             # file
ip -br a | wget {auth_header_wget}--post-data=@- -O- {BASEURL}/        # command output


    █ Upload Powershell:

Invoke-RestMethod -Uri "{BASEURL}/"{auth_header_ps} -Method Post -Body "Cheers"               # string
Invoke-RestMethod -Uri "{BASEURL}/"{auth_header_ps} -Method Post -InFile "file.txt"           # file
ipconfig | Invoke-RestMethod -Uri "{BASEURL}/"{auth_header_ps} -Method Post -Body {{ $_ }}      # command output


    █ Download:

curl {BASEURL}/{{paste_id}}                                    # print to stdout
curl -o filename.txt {BASEURL}/{{paste_id}}                    # save to file

wget -O- {BASEURL}/{{paste_id}}                                # print to stdout
wget -O filename.txt {BASEURL}/{{paste_id}}                    # save to file

Invoke-RestMethod -Uri "{BASEURL}/{{paste_id}}"                                   # print to stdout
Invoke-RestMethod -Uri "{BASEURL}/{{paste_id}}" -OutFile "filename.txt"           # save to file


    █ Delete:

curl -X POST "{BASEURL}/{{paste_id}}?token={{deletion_token}}"  # delete paste



██ Encryption Examples with curl ██


    █ Upload text:

echo 'Cheers' \
  | openssl enc -aes-256-cbc -pbkdf2 -salt -base64 -pass pass:yourkey \
  | curl {auth_header_curl}-X POST -d @- {BASEURL}/


    █ Upload file:

openssl enc -aes-256-cbc -pbkdf2 -salt -pass pass:yourkey -base64 < file.txt \
  | curl {auth_header_curl}-sS -X POST {BASEURL} --data-binary @-


    █ Upload command output:

ip -br a \
  | openssl enc -aes-256-cbc -pbkdf2 -salt -pass pass:yourkey -base64 \
  | curl {auth_header_curl}-sS -X POST {BASEURL} --data-binary @-


    █ Download:

curl -s {BASEURL}/{{paste_id}} \
  | base64 -d \
  | openssl enc -d -aes-256-cbc -pbkdf2 -pass pass:yourkey



██ Adv Examples  ██


    █ Multiple commands:

{{ cmd() {{ printf "\\n# %s\\n" "$*"; "$@"; }}; \\
    cmd hostname; \\
    cmd ip -br a; \\
    }} 2>&1 | curl {auth_header_curl}-X POST {BASEURL} --data-binary @-


    █ Continous command:

(timeout --signal=INT --kill-after=5s 10s \\
    ping 127.1; \\
    echo "--- Terminated ---") | \\
    curl {auth_header_curl}-X POST --data-binary @- {BASEURL}



████ Further Information ████


Powered by linedump

Source:
    https://git.uphillsecurity.com/cf7/linedump

License:
    Apache-2.0
    https://git.uphillsecurity.com/cf7/linedump/src/branch/main/LICENSE

"""

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
