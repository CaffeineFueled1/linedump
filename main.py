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


BASEURL = os.getenv('BASEURL', 'http://127.0.0.1:8000')
DESCRIPTION = os.getenv('DESCRIPTION', 'CLI-only pastebin powered by linedump.com')
MAX_FILE_SIZE_MB = int(os.getenv('MAX_FILE_SIZE_MB', '50'))
RATE_LIMIT = os.getenv('RATE_LIMIT', '50/hour')
URL_PATH_LENGTH = int(os.getenv('URL_PATH_LENGTH', '6'))

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="linedump", version="1.0.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

MAX_FILE_SIZE = MAX_FILE_SIZE_MB * 1024 * 1024  # Convert MB to bytes

def generate_random_path(length: int = None) -> str:
    if length is None:
        length = URL_PATH_LENGTH
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def get_client_ip(request: Request) -> str:
    x_real_ip = request.headers.get("X-Real-IP")
    if x_real_ip:
        return x_real_ip.strip()
    return request.client.host


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
async def upload_text(request: Request):
    
    body = await request.body()
    content = body.decode('utf-8', errors='ignore')
    
    if not validate_content(content):
        raise HTTPException(status_code=400, detail="Invalid content")
    
    if not content.strip():
        raise HTTPException(status_code=400, detail="Empty content")
    
    random_path = generate_random_path()
    while (UPLOAD_DIR / random_path).exists():
        random_path = generate_random_path()
    
    file_path = UPLOAD_DIR / random_path
    
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)

        return f"{BASEURL}/{random_path}\n"
    
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to save file")

@app.get("/{file_path}", response_class=PlainTextResponse)
async def get_file(file_path: str):
    if not file_path.isalnum():
        raise HTTPException(status_code=404, detail="File not found")
    
    file_location = UPLOAD_DIR / file_path
    
    if not file_location.exists() or not file_location.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    
    try:
        with open(file_location, 'r', encoding='utf-8') as f:
            content = f.read()
        return content
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to read file")

@app.get("/", response_class=PlainTextResponse)
async def root():
    return f"""LD {BASEURL}

 ████ General ████

{DESCRIPTION}

- File limit: {MAX_FILE_SIZE_MB} MB
- Rate limit: {RATE_LIMIT}
- text-only
- no server-side encryption, consider content public or use client-side encryption


████ Usage ████


    █ Upload curl:

curl -X POST -d "Cheers" {BASEURL}/                  # string
curl -X POST {BASEURL} --data-binary @- < file.txt   # file
ip -br a | curl -X POST {BASEURL} --data-binary @-   # command output


    █ Upload wget:

echo "Cheers" | wget --post-data=@- -O- {BASEURL}/   # string
wget --post-file=file.txt -O- {BASEURL}/             # file
ip -br a | wget --post-data=@- -O- {BASEURL}/        # command output


    █ Upload Powershell:

Invoke-RestMethod -Uri "{BASEURL}/" -Method Post -Body "Cheers"               # string
Invoke-RestMethod -Uri "{BASEURL}/" -Method Post -InFile "file.txt"           # file
ipconfig | Invoke-RestMethod -Uri "{BASEURL}/" -Method Post -Body {{ $_ }}      # command output


    █ Download:

curl {BASEURL}/{{path}}

wget -O- {BASEURL}/{{path}}

Invoke-RestMethod -Uri "{BASEURL}/{{path}}"



██ Encryption Examples with curl ██


    █ Upload text:

echo 'Cheers' \
  | openssl enc -aes-256-cbc -pbkdf2 -salt -base64 -pass pass:yourkey \
  | curl -X POST -d @- {BASEURL}/


    █ Upload file:

openssl enc -aes-256-cbc -pbkdf2 -salt -pass pass:yourkey -base64 < file.txt \
  | curl -sS -X POST {BASEURL} --data-binary @-


    █ Upload command output:

ip -br a \
  | openssl enc -aes-256-cbc -pbkdf2 -salt -pass pass:yourkey -base64 \
  | curl -sS -X POST {BASEURL} --data-binary @-


    █ Download:

curl -s {BASEURL}/{{path}} \
  | base64 -d \
  | openssl enc -d -aes-256-cbc -pbkdf2 -pass pass:yourkey



██ Adv Examples  ██


    █ Multiple commands:

{{ cmd() {{ printf "\\n# %s\\n" "$*"; "$@"; }}; \\
    cmd hostname; \\
    cmd ip -br a; \\
    }} 2>&1 | curl -X POST {BASEURL} --data-binary @-


    █ Continous command:

(timeout --signal=INT --kill-after=5s 10s \\
    ping 127.1; \\
    echo "--- Terminated ---") | \\
    curl -X POST --data-binary @- {BASEURL}



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
