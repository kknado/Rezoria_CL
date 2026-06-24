# Rezoria CL Loader

Public repo for the Rezoria CL encrypted payload and Lua loader.

The plaintext `REZORIA_CL.lua` source is intentionally not committed here. The loader downloads `payload/REZORIA_CL.chacha20.hex`, decrypts it locally, then executes it in OTClient/vBot.

## Install

1. Set the shared 64-character hex key locally in OTClient storage:

```lua
storage.rezoriaOSKey = "PASTE_SHARED_KEY_HERE"
```

2. Load `loader.lua` in vBot.

## Security Note

This protects the source from being readable in a public GitHub repository. It does not make the code unrecoverable from a fully controlled client. Anyone who receives the key and can modify their client can still inspect the decrypted script at runtime.

## Updating Payload

Run locally:

```powershell
python tools/encrypt_payload.py --source REZORIA_CL.lua --out payload/REZORIA_CL.chacha20.hex --key-file RezoriaOS.key
```

Commit and push the updated payload.

