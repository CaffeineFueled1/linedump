# Linedump

**CLI-only text pastebin service.**

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

**Ideas**:
- integrated retention/purge function

**Not planned**:
- GUI *(work around possible, WIP)*
- media besides text (abuse potential and moderation effort too high - there are other projects for it available)

---

## Usage

Check [linedump.com](https://linedump.com) for now - coming soon.

---

## Installation

Use with reverse-proxy and HTTPS!

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DOMAIN` | Domain name used in the application responses and examples | `linedump.com` | No |
| `DESCRIPTION` | Application description displayed in the root endpoint | `CLI-only pastebin powered by linedump.com` | No |
| `MAX_FILE_SIZE_MB` | Maximum file size limit in megabytes | `50` | No |
| `RATE_LIMIT` | Rate limit for uploads (format: "requests/timeframe") | `50/hour` | No |
| `URL_PATH_LENGTH` | Length of generated URL paths (number of characters) | `6` | No |

---

## Security

For security concerns or reports, please contact via `hello a t uphillsecurity d o t com` [gpg](https://uphillsecurity.com/gpg).

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
