# Linedump

**CLI-only text pastebin service.**

[Issue tracker](https://git.uphillsecurity.com/cf7/linedump/issues) | `Libera Chat #linedump`

- Status: Beta - expect minor changes
- Instance: [linedump.com](https://linedump.com/)
- Inspired by:
    - [0x0.st](https://git.0x0.st/mia/0x0)
    - [transfer.sh](https://github.com/dutchcoders/transfer.sh)

**Note:** content is stored unencrypted on the server - consider it public! - Use client-side encryption example in *Usage* section.

---

## Features

**Available**:
- save and share content via CLI
- up- and download in CLI possible
- rate-limits
- optional auth token for paste creation
- logging

**Ideas**:
- integrated retention/purge function

**Not planned**:
- GUI *(work around possible, WIP)*
- media besides text (abuse potential and moderation effort too high - there are other projects for it available)

---

## Usage

```text
    █ Upload curl:

curl -X POST -d "Cheers" https://linedump.com/                  # string
curl -X POST https://linedump.com --data-binary @- < file.txt   # file
ip -br a | curl -X POST https://linedump.com --data-binary @-   # command output


    █ Upload wget:

echo "Cheers" | wget --post-data=@- -O- https://linedump.com/   # string
wget --post-file=file.txt -O- https://linedump.com/             # file
ip -br a | wget --post-data=@- -O- https://linedump.com/        # command output


    █ Upload Powershell:

Invoke-RestMethod -Uri "https://linedump.com/" -Method Post -Body "Cheers"               # string
Invoke-RestMethod -Uri "https://linedump.com/" -Method Post -InFile "file.txt"           # file
ipconfig | Invoke-RestMethod -Uri "https://linedump.com/" -Method Post -Body { $_ }      # command output


    █ Download:

curl https://linedump.com/{path}                                    # print to stdout
curl -o filename.txt https://linedump.com/{path}                    # save to file

wget -O- https://linedump.com/{path}                                # print to stdout
wget -O filename.txt https://linedump.com/{path}                    # save to file

Invoke-RestMethod -Uri "https://linedump.com/{path}"                                   # print to stdout
Invoke-RestMethod -Uri "https://linedump.com/{path}" -OutFile "filename.txt"           # save to file


    █ Delete:

curl -X POST "https://linedump.com/{path}?token={deletion_token}"  # delete paste



██ Encryption Examples with curl ██


    █ Upload text:

echo 'Cheers'   | openssl enc -aes-256-cbc -salt -pbkdf2 -base64 -pass pass:yourkey   | curl -X POST -d @- https://linedump.com/


    █ Upload file:

openssl enc -aes-256-cbc -pbkdf2 -salt -pass pass:yourkey -base64 < file.txt   | curl -sS -X POST https://linedump.com --data-binary @-


    █ Upload command output:

ip -br a   | openssl enc -aes-256-cbc -pbkdf2 -salt -pass pass:yourkey -base64   | curl -sS -X POST https://linedump.com --data-binary @-


    █ Download:

curl -s https://linedump.com/{path}   | base64 -d   | openssl enc -d -aes-256-cbc -pbkdf2 -pass pass:yourkey



██ Authentication Examples ██

If the instance has authentication enabled, include Bearer token:

    █ curl:

curl -H "Authorization: Bearer YOUR_TOKEN" -X POST -d "Cheers" https://linedump.com/

    █ wget:

wget --header="Authorization: Bearer YOUR_TOKEN" --post-data="Cheers" -O- https://linedump.com/

    █ Powershell:

Invoke-RestMethod -Uri "https://linedump.com/" -Headers @{"Authorization"="Bearer YOUR_TOKEN"} -Method Post -Body "Cheers"



██ Adv Examples  ██


    █ Multiple commands:

{ cmd() { printf "\n# %s\n" "$*"; "$@"; }; \
    cmd hostname; \
    cmd ip -br a; \
    } 2>&1 | curl -X POST https://linedump.com --data-binary @-


    █ Continous command:

(timeout --signal=INT --kill-after=5s 10s \
    ping 127.1; \
    echo "--- Terminated ---") | \
    curl -X POST --data-binary @- https://linedump.com
```

---

## Installation

> [!IMPORTANT]
> **Production Deployment:** Use a reverse-proxy (nginx, caddy) with TLS/HTTPS! Rate-limiting and logging features require the `X-Real-IP` header from a reverse proxy to function correctly. Less critical for local or trusted environments.

### Docker

**Simple / Testing**

`docker run -d -p 127.0.0.1:8000:8000 -v /path/to/uploads:/app/uploads git.uphillsecurity.com/cf7/linedump:latest`

Open `http://127.0.0.1:8000`

**More advanced example with Podman**

```bash
podman run --replace -d --restart=unless-stopped \
    --name linedump \
    -e BASEURL="https://linedump.com" \
    --userns=keep-id \
    --read-only \
    --cap-drop=ALL \
    --security-opt no-new-privileges:true \
    -p 127.0.0.1:8000:8000 \
    -v linedump:/app/uploads \
    git.uphillsecurity.com/cf7/linedump:latest
```

### Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `BASEURL` | Base URL used in the application responses and examples | `http://127.0.0.1:8000` | No |
| `DESCRIPTION` | Application description displayed in the root endpoint | `CLI-only pastebin powered by linedump.com` | No |
| `MAX_FILE_SIZE_MB` | Maximum file size limit in megabytes | `50` | No |
| `RATE_LIMIT` | Rate limit for uploads (format: "requests/timeframe") | `50/hour` | No |
| `URL_PATH_LENGTH` | Length of generated URL paths (number of characters) | `6` | No |
| `UPLOAD_TOKENS` | Comma-separated list of Bearer tokens for upload authentication (if set, uploads require valid token) | _(disabled)_ | No |
| `LOGGING_ENABLED` | Enable structured JSON logging to file and stdout | `false` | No |
| `LOG_LEVEL` | Logging level (INFO, WARNING, ERROR) | `INFO` | No |

Create a secure token with: `openssl rand -base64 32`.

---

## Security

For security concerns or reports, please contact via `hello a t uphillsecurity d o t com` [gpg](https://uphillsecurity.com/gpg).

---

## Notes

- [Github Mirror available](https://github.com/CaffeineFueled1/linedump)
- [Rate Limit Testing Script](https://git.uphillsecurity.com/cf7/Snippets/wiki/bash-linedump-ratelimit-test.-)

---

## License

**Apache License**

Version 2.0, January 2004

http://www.apache.org/licenses/

- ✅ Commercial use
- ✅ Modification
- ✅ Distribution
- ✅ Patent use
- ✅ Private use
- ✅ Limitations
- ❌Trademark use
- ❌Liability
- ❌Warranty
