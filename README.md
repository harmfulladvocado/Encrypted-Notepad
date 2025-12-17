# Encrypted Notepad

A simple, secure desktop notepad application that encrypts your notes with password protection.  Built with Python and Tkinter.

## Features

- **Strong Encryption**: Uses SHA-256-based key derivation and XOR cipher to encrypt your notes
- **Master Password**: Optional master password system for quick access to multiple notes
- **Per-Note Passwords**: Set unique passwords for individual notes for extra security
- **Dark Mode**: Toggle between light and dark themes for comfortable viewing
- **Simple Interface**: Clean, distraction-free text editor
- **Keyboard Shortcuts**: Full keyboard navigation support
- **Cross-Platform**: Works on Windows, macOS, and Linux

## Installation

1. Ensure you have Python 3.6+ installed
2. Clone or download this repository
3. Run the application: 

```bash
python encrypted_notepad.py
```

No additional dependencies required - uses only Python standard library! 

## Usage

### First Launch

On first launch, you'll be prompted to set a master password. This is optional but recommended for convenience.

### Creating a New Note

1. Click **File → New** (or press `Ctrl+N`)
2. Type your content
3. Click **File → Save** (or press `Ctrl+S`)
4. Choose whether to encrypt with your master password or set a custom password
5. Select where to save your encrypted note file

### Opening an Encrypted Note

1. Click **File → Open** (or press `Ctrl+O`)
2. Select your encrypted note file
3. Enter the password used to encrypt it

### Master Password

Set or change your master password via **Settings → Set/Change Master Password** (or press `Ctrl+M`).

When saving notes, you can choose to: 
- **Use master password**: Quick encryption with your master password
- **Use custom password**: Set a unique password for this specific note

### Dark Mode

Toggle dark mode via **Settings → Toggle Dark Mode** (or press `Ctrl+D`).

## Keyboard Shortcuts

| Action | Windows/Linux | macOS |
|--------|---------------|-------|
| New file | `Ctrl+N` | `Cmd+N` |
| Open file | `Ctrl+O` | `Cmd+O` |
| Save | `Ctrl+S` | `Cmd+S` |
| Save As | `Ctrl+Shift+S` | `Cmd+Shift+S` |
| Exit | `Ctrl+Q` | `Cmd+Q` |
| Master Password | `Ctrl+M` | `Cmd+M` |
| Toggle Dark Mode | `Ctrl+D` | `Cmd+D` |

## File Format

Encrypted notes are saved with the `.enc` extension by default. The file format includes: 
- Header identifier
- Random salt (hex-encoded)
- Encrypted content (hex-encoded)

## Security Notes

- The master password hash is stored in `~/.enc_notepad_master.json`
- Each note uses a random 16-byte salt for key derivation
- The encryption uses SHA-256 for key stretching
- Never share your passwords or encrypted files without understanding the security implications
- This is a simple encryption implementation suitable for personal notes, not classified information

## Technical Details

**Encryption Method**: 
- Key derivation using SHA-256 with salt
- XOR cipher with derived keystream
- Random salt generated for each encryption

**Storage**:
- Master password stored as salted SHA-256 hash
- Notes saved as plaintext hex-encoded encrypted data
- No plaintext data stored on disk

## Requirements

- Python 3.6 or higher
- tkinter (included with most Python installations)

## Platform Support

- ✅ Windows
- ✅ macOS  
- ✅ Linux (with Tk/Tcl support)
