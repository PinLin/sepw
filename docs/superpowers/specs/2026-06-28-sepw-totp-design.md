# sepw `totp` 指令設計

日期：2026-06-28

## 目標

讓 sepw 除了存取密碼外，也能直接以儲存在 Secure Enclave 的種子產生 TOTP
驗證碼（含 8 位數）。種子解密後在 process 內完成 HMAC 運算，只印出驗證碼，
不把種子寫到 stdout，也不經過其他程序的 argv，維持 sepw「種子永不離開晶片」
的安全模型，且不引入任何外部依賴（只用 Apple 自家框架 CryptoKit）。

## 非目標（YAGNI）

- 不實作 QR code 掃描或 `otpauth://` 的「寫入/產生」。種子仍由使用者透過
  既有的 `sepw add` 存入。
- 不顯示倒數秒數、下一組碼或進度條，stdout 只有驗證碼。
- 不做 HOTP（計數器型）。

## 指令介面

```
sepw totp <name> [--digits N] [--period S] [--algorithm SHA1|SHA256|SHA512]
```

- 種子以既有的 `sepw add <name>` 存入，內容可為純 base32 種子，或整串
  `otpauth://totp/...` URI。
- `totp` 只負責讀取既有 entry、解密、運算並印出驗證碼，不新增儲存路徑。
- stdout 只印出驗證碼數字（與 `get` 一致，pipe-friendly）；狀態與錯誤走 stderr。
- Touch ID 提示文字：`Authenticate to generate TOTP for "<name>"`。

範例：
```bash
sepw add my-totp                 # 貼上 base32 種子或 otpauth:// URI
sepw totp my-totp                # 預設 6 位
sepw totp my-totp --digits 8     # 8 位
```

## 種子格式自動偵測

解密得到字串後：

- 若以 `otpauth://` 開頭 → 解析 URI 的 query 參數，取 `secret`（必填）、
  `digits`、`period`、`algorithm`（皆選填）。
- 否則整個字串視為 base32 種子。

### 參數優先序

CLI 旗標 > otpauth URI 帶的值 > 內建預設。

內建預設（RFC 6238）：`digits = 6`、`period = 30`、`algorithm = SHA1`。

## 運算（RFC 6238 / RFC 4226）

1. **base32 解碼**種子：大小寫不分、容忍內嵌空白、容忍尾端 `=` padding；
   出現非 base32 字元則視為錯誤。
2. `counter = floor(currentUnixTime / period)`，編成 8-byte big-endian。
3. `hmac = HMAC(algorithm, key = 解碼後種子, message = counter)`，
   使用 CryptoKit 的 `HMAC<Insecure.SHA1>` / `HMAC<SHA256>` / `HMAC<SHA512>`。
4. **動態截斷**：取 `hmac` 最後一個 byte 的低 4 bit 當 offset，自該 offset
   取 4 bytes，遮掉最高位得到 31-bit 整數。
5. `code = truncated mod 10^digits`，左補零到 `digits` 位後輸出。

## 錯誤處理（沿用現有 `die()` → stderr + exit 1）

- 找不到 entry。
- 種子缺失（otpauth URI 無 `secret`）或非合法 base32。
- `digits` 不在 6–8 範圍。
- `period` 非正整數。
- `algorithm` 不是 SHA1 / SHA256 / SHA512。
- 解密失敗（Touch ID 取消等，沿用 `decryptWithSE` 既有訊息）。

## 程式碼落點

全部加進現有單檔 `sepw.swift`（目前 227 行，維持單檔設計）：

- 新增 `base32Decode(_:) -> Data?`。
- 新增 TOTP 運算函式（含參數解析與依 algorithm 分派 HMAC）。
- 新增 `totpItem(name:options:)`：解密 → 偵測格式 → 套用優先序 → 運算 → 印碼。
- `switch` 新增 `case "totp"`，解析 `<name>` 與旗標。
- `usage()` 補一行說明。

預估新增約 60–70 行，單檔仍在合理範圍，不另拆檔。

## 測試

以 RFC 6238 附錄 B 的官方測試向量驗證運算正確性：

- 種子（ASCII）`12345678901234567890`，對應 base32 為 `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ`。
- 在指定時間戳（如 `59`、`1111111109`、`1234567890` 等）下，
  SHA1 對應的 8 位驗證碼為已知值（例如 t=59 → `94287082`）。
- 同樣涵蓋 SHA256 / SHA512 的對應種子與已知碼。

由於 `totp` 取目前系統時間，測試會以可注入時間戳的內部運算函式為測試對象
（運算與系統時間取得分離），確保以固定時間戳能比對官方向量。
