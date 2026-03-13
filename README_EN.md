# SakuraMapper

[Русский](README.md)

---

Server-sided PE mapper. The server handles everything — parses the PE, maps sections, applies relocations to whatever base the client allocated, strips `.reloc`, encrypts the image, sends it over WebSocket. The client writes it into the target and runs it.

The point: if someone dumps the mapped region, there's no relocation data to recover. The image was already relocated to the right address before it ever left the server.

---

## Licenses

Keys are stored in `keys.json`. Two types:

- `initial` — key has been issued but not yet used. On first auth the server grabs the client's HWID and permanently binds the key to that machine
- `bound` — key is locked, any auth from a different machine is rejected

HWID is derived from CPU ID, C: volume serial, and computer name, hashed with FNV-1a.

---

## Building

Visual Studio 2022, Windows SDK, x64.

Build order: `payload` → `server` → `client`. Everything is in `SakuraMapper.sln`.

---

## Running

```
server.exe --dll payload.dll --port 9150
client.exe --host 127.0.0.1 --port 9150 --key SAKURA-TEST-KEY-0001 --target notepad.exe
```

`--key` and `--target` are optional, the client will prompt if omitted. If `keys.json` doesn't exist on first launch, a test key `SAKURA-TEST-KEY-0001` is created automatically.

---

Requires admin. x64 only.
