## Git Push Guide

### Current Status:
✅ All changes committed to local repository
❌ Push to GitHub requires authentication

### Commit Details:
- **Commit Hash:** 3a235c5
- **Files Changed:** 77 files
- **Insertions:** 17,283 lines
- **Remote:** https://github.com/Mino1214/macroServer

### To Push to GitHub:

#### Option 1: Use GitHub Personal Access Token (Recommended)

1. **Generate a token** at: https://github.com/settings/tokens
   - Click "Generate new token (classic)"
   - Select scopes: `repo` (full control of private repositories)
   - Copy the token

2. **Push with token:**
   ```bash
   cd /home/myno/바탕화면/myno/macroServer
   git push https://YOUR_TOKEN@github.com/Mino1214/macroServer main
   ```

3. **Or set remote with token:**
   ```bash
   git remote set-url origin https://YOUR_TOKEN@github.com/Mino1214/macroServer
   git push origin main
   ```

#### Option 2: Use SSH Key (More Secure)

1. **Generate SSH key:**
   ```bash
   ssh-keygen -t ed25519 -C "your_email@example.com"
   cat ~/.ssh/id_ed25519.pub
   ```

2. **Add to GitHub:**
   - Go to: https://github.com/settings/keys
   - Click "New SSH key"
   - Paste your public key

3. **Change remote to SSH:**
   ```bash
   cd /home/myno/바탕화면/myno/macroServer
   git remote set-url origin git@github.com:Mino1214/macroServer.git
   git push origin main
   ```

#### Option 3: Use GitHub CLI (Easiest)

```bash
# Install gh CLI if not installed
sudo apt install gh

# Authenticate
gh auth login

# Push
cd /home/myno/바탕화면/myno/macroServer
git push origin main
```

### What Was Committed:

**Major Features:**
- ✅ MariaDB integration
- ✅ User approval workflow
- ✅ Subscription management
- ✅ Seed phrase monitoring
- ✅ Modern admin dashboard
- ✅ Full seed phrase display
- ✅ Login without expiry blocking

**Files Added:**
- `db.js` - Database operations
- `seed-checker.js` - Balance monitoring
- `balance-monitor.js` - Balance tracking
- `public/admin.html` - Modern dashboard
- `docs/*` - Comprehensive documentation
- `scripts/*` - Setup and deployment scripts

### View Commit:
```bash
cd /home/myno/바탕화면/myno/macroServer
git log --stat -1
```

---

**Note:** After pushing, your code will be available at:
https://github.com/Mino1214/macroServer
