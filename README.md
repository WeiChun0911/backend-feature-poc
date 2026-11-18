# 後端特徵擷取 PoC（ASP.NET Core）

`GET /api/features` 回傳一次 request 到達 ASP.NET Core 時，應用程式能直接觀察到的訊號。這個 PoC 不儲存擷取資料，也不回傳 Cookie、Authorization 或 request body；response 設為 `no-store`。啟用 Google 登入後，ASP.NET Core 會使用短期登入 Cookie 維持登入狀態。

## 執行

需要 .NET 10 SDK：

```sh
dotnet dev-certs https --trust
dotnet run
curl -i http://localhost:5082/api/features
```

HTTP listener 在 port 5082；本機 Kestrel HTTPS listener 在 port 5081。要看 Chrome 的 TLS 特徵，請在 Chrome 開 `https://localhost:5081/api/features`。若不信任本機開發憑證，先執行 `dotnet dev-certs https --trust` 並完成 macOS 的信任提示。可以用 `curl -k https://localhost:5081/api/features` 驗證 TLS 擷取，但那會得到 curl 的指紋，不是 Chrome 的。

## Google 登入與部署

公開 HTTPS 部署時必須開啟 Google 登入；程式會驗證 Google OIDC ID token，並只接受 Google 已驗證的 `@titansoft.com.tw` email。Google OAuth 用戶端密鑰只能透過環境設定或 AWS Systems Manager Parameter Store 注入，不要提交到原始碼。

Google Cloud Console 的 Web application OAuth client 需登記以下回呼網址：

```text
https://willywcliu.duckdns.org/signin-oidc
```

部署時設定：

```text
Authentication__RequireGoogleAuth=true
Authentication__Google__ClientId=<OAuth client ID>
Authentication__Google__ClientSecret=<OAuth client secret>
Tls__CertificatePath=/etc/backend-feature-poc/tls/fullchain.pem
Tls__PrivateKeyPath=/etc/backend-feature-poc/tls/privkey.pem
```

AWS 部署將 Google OAuth 用戶端資料放在 Systems Manager Parameter Store：`/backend-feature-poc/google-client-id`（String）和 `/backend-feature-poc/google-client-secret`（SecureString）。EC2 role 只可讀取這兩個參數路徑；不要把 client secret 放進 Git 或聊天內容。

當 TLS 憑證路徑有設定時，Kestrel 會直接在 `0.0.0.0:443` 終止 TLS，以便保留 ClientHello 擷取；同時若未啟用 Google 登入，應用程式會拒絕啟動。未設定憑證時則使用 localhost 開發 listener（HTTP 5082、HTTPS 5081）。

OAuth 登入只請求 `openid`、`email`、`profile`，不要求存取 Google Drive 或其他使用者資料 API。

### TShark TCP SYN 擷取（PoC）

EC2 安裝 Amazon Linux 的 `wireshark-cli` 後，使用 [`infra/backend-feature-poc-tshark.service`](infra/backend-feature-poc-tshark.service) 啟動獨立的受限 systemd 服務。它只擷取目的 port 443 的初始 SYN，將選定欄位輸出到本機 FIFO，不寫入 pcap 檔；ASP.NET Core 以背景服務讀取 FIFO。主服務只需要 [`infra/backend-feature-poc.service.d-tshark-order.conf`](infra/backend-feature-poc.service.d-tshark-order.conf) 指定啟動順序：

```text
TcpCapture__Enabled=true
TcpCapture__StreamPath=/run/backend-feature-poc-tshark/fields.fifo
```

只有 TShark 擷取服務取得受限的 `CAP_NET_RAW` 和 `CAP_NET_ADMIN`；ASP.NET Core 主服務的 `NoNewPrivileges` 與 capability 設定不變。若 TShark 或 FIFO 不可用，Web App 仍可啟動，但會記錄錯誤且 `tcpSynFingerprint` 為 null。特徵依來源／目的 IP 和 port 對應到 Kestrel 連線，暫存最多 30 分鐘；HTTP/2 同一連線上的請求共用該 SYN 特徵。

API 欄位包含初始視窗、MSS、SACK 是否允許、TCP Timestamp 是否存在、Window Scale、TCP options 順序和封包擷取時間。這是單機 PoC；服務重啟會清空暫存，沒抓到 SYN 或端點對不上時不會有欄位值。

回傳內容包括：

- HTTP method、protocol、host、path、部分瀏覽器標頭與 Client Hints
- App 所見的 remote IP/port、connection ID
- TLS 協定與協商後的 cipher suite（若 TLS 由支援此 feature 的 Kestrel 端點終止）
- JA3、JA3 原始欄位字串、JA4（僅 HTTPS Kestrel 直連、ClientHello 完整落在第一個 TLS record 時）
- Server runtime/OS/架構，獨立放在 `serverRuntime`，這些不是訪客特徵

## 對照 survey 的後端訊號

| Survey 訊號 | ASP.NET Core PoC 可見性 | 條件與後續驗證 |
|---|---|---|
| IP / IPv4-v6 | 可讀 `RemoteIpAddress` | App 直連時是 TCP 對端；經 CDN/Ingress 時可能是代理。轉送 IP 只能接受可信代理寫入的 forwarded headers。 |
| Geo / ASN / ISP / VPN / Proxy / Tor | 不能由 IP 欄位直接得出 | 需自備或採購 IP intelligence 資料來源；另需評估準確率、更新及使用授權。 |
| TLS version / negotiated cipher | Kestrel TLS 終止時可讀 | 若 TLS 在 CDN/Ingress 終止，App 看不到瀏覽器到邊緣節點的握手。 |
| TLS ClientHello / JA3 / JA4 | 本機 PoC 可在 Kestrel HTTPS 端點計算 | Go `crypto/tls` 提供 ClientHello callback；.NET 10 Kestrel 也有 raw ClientHello callback。此 PoC 的 .NET 10 callback 只收到第一個 record fragment；跨多個 fragment 的 ClientHello 會略過。若要部署，應在公司實際 TLS 終止點再驗證完整度。 |
| HTTP headers / Client Hints / HTTP version | PoC 可讀 allowlist headers 與 `Request.Protocol` | Header 內容可能被瀏覽器政策或代理改寫；本 PoC 不把標頭順序當成可靠的 wire-level 順序。 |
| TCP SYN options / window / timestamps / SACK | 可透過 TShark 擷取後依四元組對應 Kestrel 連線 | 需要主機封包擷取權限；只在看到新的 SYN 時更新，需處理連線重用和端點關聯。 |
| Request interval / frequency / endpoint sequence / duration | 可由伺服器端事件再計算 | 需定義訪客/session 關聯鍵、事件儲存、聚合窗口與保留期；本 PoC 刻意不建立追蹤資料庫。 |
| Historical signals | 可由持續保存的事件聚合 | 屬於資料模型與保存政策，不是語言或 HTTP framework 本身的特徵。 |

## 建議的驗證步驟

1. 先用 `curl -k https://localhost:5081/api/features`，確認 JSON 有 `clientHelloFingerprint.ja3`、`ja3String`、`ja4`；這是 curl 的 TLS 指紋。
2. 用 Chrome 開 `https://localhost:5081/api/features`，讀取瀏覽器自己的 JA3/JA4。和 curl 結果不同是預期現象，因為指紋反映 TLS client 實作。
3. 將 PoC 部署到公司測試環境，經正式 CDN/Ingress 路徑再請求一次，確認指紋究竟代表 Chrome 還是代理。
4. 若要看到 `tcpSynFingerprint`，請建立一條新的瀏覽器 TCP 連線再登入查看；HTTP/2 會重用連線，單純刷新既有分頁不一定會送出新的 SYN。

## 結論

JA3/JA4 是有用的 TLS client 軟體堆疊訊號，可補充 bot/risk 判斷，但不等於穩定的個人或裝置 ID；相同瀏覽器/TLS stack 會共享指紋，版本或代理也會改變指紋。依 survey 的範圍，.NET 10 已能在本機 Kestrel 驗證 JA3/JA4。公司環境要看到訪客瀏覽器的值，必須在 TLS 仍由自家 Kestrel 終止時擷取，或由 CDN/Ingress 提供該欄位。

此 PoC 依公開 JA3/JA4 演算法規格自行解析；FoxIO JA4 上游程式碼另有 FoxIO License 1.1，若未來改為引用/複製上游程式碼或納入正式產品，需先確認適用授權。
