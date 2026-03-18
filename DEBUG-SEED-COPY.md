## 🔍 Debug Guide for Full Seed Phrase Display

### Current Status:
✅ Code has been updated with full seed phrase display
✅ Code has been updated with debug logging
✅ Nginx is pointing to the correct folder

### Testing Steps:

1. **Clear Browser Cache Completely:**
   ```
   - Press Ctrl + Shift + Delete
   - Select "Cached images and files"
   - Click "Clear data"
   
   OR
   
   - Press Ctrl + Shift + R (force refresh)
   ```

2. **Open Browser Console (F12):**
   - Go to Console tab
   - Keep it open while testing

3. **Visit Admin Page:**
   ```
   http://nexus001.vip/admin.html
   ```

4. **Login and Go to Seeds Section:**
   - Login as master account
   - Scroll to "수신 시드 문구" section

5. **Check Console Output:**
   - You should see:
     ```
     [RENDER] Total seeds: X
     [RENDER] First seed: {no: ..., phrase: "...", ...}
     [RENDER] Stored seeds in map: X
     [RENDER] Sample from map: word1 word2 word3...
     ```

6. **Click a Copy Button (📋):**
   - Click on any "#1 📋" or similar
   - Check console for:
     ```
     [COPY] Seed number: 1
     [COPY] seedsDataMap: {1: "word1 word2...", ...}
     [COPY] Found phrase: XX chars
     ```

7. **Check the Alert:**
   - Alert should show:
     ```
     ✅ 시드 #1 복사 완료!
     
     전체 시드 문구:
     word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12
     ```

### If It Still Doesn't Work:

**Please share:**
1. What do you see in the browser console? (F12 → Console tab)
2. What error message appears (if any)?
3. What does the alert show when you click copy?

### File Location:
```
/home/myno/바탕화면/myno/macroServer/public/admin.html
```

### Nginx Config:
```
root /home/myno/바탕화면/myno/macroServer/public;
```

They match, so no file copying is needed!
