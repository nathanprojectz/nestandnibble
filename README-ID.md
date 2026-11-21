# Nest & Nibble — Cloudflare deployment

## Isi paket
- `public/index.html`: aplikasi yang diberikan, dipertahankan.
- `public/nn-cloudflare.js`: adapter kompatibilitas untuk API database yang dipakai aplikasi.
- `src/index.js`: Worker API + static assets + validasi Cloudflare Access JWT.
- `schema.sql`: tabel D1.
- `wrangler.toml`: konfigurasi Worker dan binding D1.

## Langkah deploy
1. Buat D1 database bernama `nest-nibble-db` di Cloudflare.
2. Jalankan `npx wrangler d1 execute nest-nibble-db --remote --file=./schema.sql`.
3. ID database D1 sudah dimasukkan ke `wrangler.toml` untuk akun Cloudflare yang terhubung saat ini.
4. Buat Cloudflare Access application untuk hostname website ini. Lindungi seluruh hostname, bukan hanya `/api`, agar semua API request mendapat header `Cf-Access-Jwt-Assertion`.
5. Tambahkan Worker secrets/vars (API akan menolak request sampai keduanya tersedia):
   - `ACCESS_TEAM_DOMAIN`: misalnya `contoh.cloudflareaccess.com` (tanpa https://).
   - `ACCESS_AUD`: AUD tag dari Access application.
6. Deploy dari root folder:
   - `npx wrangler deploy`
7. Arahkan custom domain ke Worker melalui dashboard Cloudflare atau konfigurasi route.

## Penting: data awal
Data aplikasi yang sekarang tersimpan di localStorage browser tidak otomatis masuk ke D1. Login dan ekspor backup dari perangkat lama, lalu gunakan fitur restore setelah backend aktif; untuk migrasi multi perangkat, lakukan satu kali dari perangkat yang memiliki data paling lengkap.

## Keamanan akun aplikasi
Versi HTML saat ini masih menyimpan daftar ID dan hash PIN di JavaScript frontend. Ini bukan autentikasi server yang aman untuk sistem kasir publik. Cloudflare Access pada paket ini melindungi akses website/API di tingkat identitas. Sebelum dipakai untuk data operasional sensitif, pindahkan autentikasi per-role ke Worker dan jangan menganggap PIN frontend sebagai kontrol keamanan.


## Status persiapan
Database D1 `nest-nibble-db` sudah dibuat di akun Cloudflare yang terhubung dan tabel `records` beserta indeks sudah diterapkan. File `index.html` juga sudah diubah agar adapter D1 dimuat sebelum kode aplikasi memanggil `initSync()`.
