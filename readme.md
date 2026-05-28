# main.py

Decrypt, deserialize, modify, and re-encrypt Rocket League SaveData files.

Credits to [Drogebot/RocketRP](https://github.com/Drogebot/RocketRP) for the AES key and binary format research.

## Why

Since Rocket League added EAC, reading process memory to grab inventory, keybinds, camera settings is basically impossible now. SaveData files contians a lot of useful stuff that can be used as safe backend for plugins, bakkesmod alternatives, stat trackers, or anything that needs to peek at player data without touching the game process.

## Requirements

```
pip install pycryptodome
```

## Usage

**Decrypt a .save file to JSON:**
```
python decrypt_savedata.py file.save -o output.json
```

**Re-encrypt a modified JSON back to .save:**
```
python decrypt_savedata.py output.json --encrypt -o modified.save
```

**Flags:**
| Flag | Effect |
|------|--------|
| `-o <path>` | Output file path |
| `--encrypt` | Serialize JSON → .save (input must be .json) |
| `--compact` | Minified JSON (no indentation) |
| `--no-crc` | Skip CRC mismatch warning |

## Notes

- Round-tripped `.save` files may differ in size from the original but should be functionally identical.
- I'm not sure how reliable the re encryption is and if the game recognizes it.
