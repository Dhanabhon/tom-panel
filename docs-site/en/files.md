# Files & Access

## File Manager

Navigate to your site → **Files & Access** to upload, edit, rename, copy, move, and delete files.

### Security guarantees

- All operations are confined to your site's directory — no path escapes
- Archives are validated before extraction (symlinks and bomb patterns rejected)
- Deleted files go to **Trash** (recoverable for 7 days)

### Common tasks

| Task | How |
|---|---|
| Upload a file | Click the upload area or drag-and-drop |
| Edit a text file | Click the filename, edit inline, click Save |
| Create a directory | Enter a name, choose "Directory", click Create |
| Archive files | Check the boxes, enter a name, click "Archive selected" |
| Extract an archive | Upload a `.tar.gz`, TomPanel validates and extracts it |
| Restore from trash | Scroll to the Trash section, click Restore |

## SFTP access

Each site can have an SFTP account with chrooted access.

### Enable SFTP

1. Go to your site → **Files & Access**
2. Scroll to **SFTP access**
3. Click **Enable SFTP**

### Connect

```bash
sftp tp_yoursiteid@your-server
```

### Security

- Chrooted to your site's directory only
- Shell, port forwarding, tunneling, and agent forwarding are disabled
- Password and SSH public key authentication supported
- Password rotation requires recent re-authentication (step-up)

### Manage SSH keys

1. In **Files & Access**, paste your public key (e.g., `ssh-ed25519 AAAA… you@laptop`)
2. Click **Add key**
3. Connect with your private key — no password needed
