# 受信PWA 動作確認手順（QR生成込み）

この手順は **QRファイルデコード** と **カメラ実機デコード** を確認します。
HTTPSはiOS向けに必須です（Android/ChromeはHTTPでも可）。

## 0) 準備（ゼロベース）

1. リポジトリを取得
   ```
   git clone <repo-url>
   cd airgap-xfer
   ```
2. mise をインストール
   - macOS: `brew install mise`
   - Linux: `curl https://mise.jdx.dev/install.sh | sh`
3. mise の環境を有効化
   ```
   eval "$(mise activate bash)"
   ```
4. 必要なツールをインストール（bun, mkcert, rust）
   ```
   mise install
   ```
5. web/receiver-pwa で依存をインストール
   ```
   cd web/receiver-pwa
   mise exec -- bun install
   cd ../..
   ```

## 1) HTTPS開発サーバ起動（iOS向け）

```
DEV_HOST=<PCのIP> scripts/dev_https_pwa.sh
```

- `<PCのIP>` は同一LAN上のIP（例: `192.168.1.10`）
- 既定ポートは `5173`（必要なら `PORT=4173` などで変更）

### WSLでViteを起動している場合（Windows向けポートフォワード）

WSL2は仮想NATなので、**WSLのIPではスマホから到達できません**。  
Windows側でポートフォワードを張り、**WindowsのLAN IP** を使います。

1. WSL側でリポジトリルートへ移動し、PowerShell 用パスを取得
   ```
   cd airgap-xfer
   wslpath -w "$(pwd)/scripts/wsl_portproxy.ps1"
   ```
2. Windows PowerShell を **管理者として起動** し、以下を実行
   ```
   powershell -ExecutionPolicy Bypass -File "<上で出たパス>" -ListenPort 5173
   ```
3. WindowsのLAN IPを確認
   ```
   ipconfig | findstr /R /C:"IPv4 Address"
   ```
4. **DEV_HOSTにはWindowsのLAN IP** を指定してHTTPS起動
   ```
   DEV_HOST=<WindowsのLAN IP> scripts/dev_https_pwa.sh
   ```

補足:
- WSLのIPは再起動で変わるため、再起動後は `wsl_portproxy.ps1` を再実行してください
- ポートフォワードを解除したい場合:
  ```
  powershell -ExecutionPolicy Bypass -File "<上で出たパス>" -ListenPort 5173 -Remove
  ```

### iOSにルートCAを信頼させる

1. `mkcert -CAROOT` を確認
   ```
   mise exec -- mkcert -CAROOT
   ```
2. そのディレクトリ内の `rootCA.pem` をiPhoneへコピー
3. iOS側でプロファイルをインストール
4. `設定 > 一般 > 情報 > 証明書信頼設定` で `rootCA` を信頼

## 2) QRコードを生成（テキスト）

```
mise exec -- bunx qrcode "AXFR_TEST" -o /tmp/axfr-qr.png
```

- `/tmp/axfr-qr.png` をPCで開いて表示
- 別の端末で全画面表示して読み取りに使う

## 3) 受信PWAへアクセス

- PC: `https://localhost:5173`
- スマホ: `https://<PCのIP>:5173`

## 4) QRファイルのデコード確認

1. 画面の `QR image` に `/tmp/axfr-qr.png` をアップロード
2. `decoded` が表示され、結果に `AXFR_TEST` が出ることを確認

## 5) カメラでのデコード確認

1. `Start camera` を押してカメラ許可
2. `AXFR_TEST` のQRをかざす
3. `decoded` と `Text: AXFR_TEST` が表示されれば成功

## 6) 参考（調整パラメータ）

`web/receiver-pwa/src/main.ts` の以下を調整できます。

- `CAMERA_CAPTURE_MAX_WIDTH`（解像度）
- `CAMERA_CAPTURE_INTERVAL_MS`（キャプチャ間隔）

## 7) よくあるトラブル

- `Camera API unavailable` : HTTPSでない / 権限拒否
- `ZXing worker failed` : 初期化失敗。リロードして再試行
- `Camera canvas unavailable` : 古いブラウザ。Chrome/Edge推奨

## 8) HTTPで動かしたい場合（Android/Chrome向けの簡易確認）

```
cd web/receiver-pwa
mise exec -- bun run dev -- --host 0.0.0.0 --port 5173
```

- Android/ChromeならHTTPでもカメラ許可が通る場合があります
  (セキュリティ設定に依存)
