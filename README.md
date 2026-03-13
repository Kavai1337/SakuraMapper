# SakuraMapper

Server-sided PE mapper. The server does all the heavy lifting — parses the PE, maps sections, applies relocations to whatever base the client allocates, strips `.reloc`, encrypts the image, and sends it over WebSocket. The client just writes it into the target and runs it.

The point: if someone dumps the injected region from memory, there's no relocation data to recover. You can't re-base it.

---

## How it works

```
client                          server
  |                               |
  |-- license + hwid ------------>|  validates key, binds hwid on first use
  |<-- auth ok (image size) ------|
  |                               |
  |  VirtualAllocEx(target)       |  client gets the actual base address
  |                               |
  |-- map request (base addr) --->|  server relocates to that exact address
  |                               |  strips .reloc, RC4 encrypts image
  |<-- mapped image + metadata ---|
  |                               |
  |  RC4 decrypt                  |
  |  WriteProcessMemory           |
  |  resolve imports              |
  |  register .pdata (SEH)        |
  |  invoke TLS callbacks         |
  |  CreateRemoteThread(DllMain)  |
```

Relocations are applied server-side and then the `.reloc` section is zeroed before anything leaves the server. The image that ends up in the target process is position-fixed — it was already relocated to the right address before transmission.

Imports are handled client-side since the server can't know what's loaded in the target process. The server sends a table of `{ dll, function, iat_rva }` entries and the client resolves them via `GetProcAddress` through a shellcode stub.

Transit is encrypted with RC4 keyed on `license_key + hwid`, so the image in-flight is tied to that specific machine and key.

---

## License keys

Keys live in `keys.json`. There are two types:

- **initial** — key has been issued but never used. On first auth, the server captures the client's HWID, locks the key to that machine, and flips it to `bound`.
- **bound** — key is permanently tied to one HWID. Any auth attempt from a different machine is rejected.

```json
[
  {
    "key": "SAKURA-XXXX-XXXX-XXXX",
    "hwid": "",
    "expires": "never",
    "active": true,
    "type": "initial"
  }
]
```

Set `"active": false` to revoke. A default test key (`SAKURA-TEST-KEY-0001`) is created automatically if `keys.json` doesn't exist.

HWID is derived from CPU ID + C: volume serial + computer name, hashed with FNV-1a.

---

## Structure

```
shared/     protocol packets, PE type definitions, RC4 + key derivation
server/     WebSocket server, PE mapper, license manager
client/     WebSocket client, HWID generation, injector + shellcode
payload/    test DLL
```

No third-party dependencies. WebSocket implementation is hand-rolled over Winsock2 (just enough for binary frames and the RFC 6455 handshake).

---

## Building

Visual Studio 2022, Windows SDK, x64.

Build order matters: `payload` → `server` → `client`. All three are in `SakuraMapper.sln`.

---

## Usage

Start the server, point it at a DLL:
```
server.exe --dll payload.dll --port 9150
```

Run the client with a license key and target process:
```
client.exe --host 127.0.0.1 --port 9150 --key SAKURA-TEST-KEY-0001 --target notepad.exe
```

Both `--key` and `--target` can be left out — the client will prompt for them interactively.

---

## Notes

- Requires admin on the client side (`OpenProcess(PROCESS_ALL_ACCESS, ...)`)
- Target must be x64
- The server needs to have the same system DLLs available as the target for import resolution to work (usually fine on Windows since DLL base addresses are per-boot, not per-process)
