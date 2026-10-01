# Pemindaian OS target dan analisis otomatis (live USB)

> Managed by **ahlikoding.com** and **satpamsiber.com** from **ahliweb.com**.

Saat USB rescue boot ke Linux Mint 22.3 XFCE live, launcher mendeteksi sistem operasi yang terpasang di disk internal PC (Linux Mint / Linux lain, Windows, macOS), memeriksanya secara **read-only**, menulis evidence schema 1.2, mengirimnya ke OpenCode Go (`mimo-v2.6-flash`), menyimpan dan menampilkan hasil analisis, menawarkan perbaikan katalog sesuai kebijakan, menulis laporan proses, lalu menjalankan Hermes. Pemindaian dan analisis berjalan tanpa input operator; perbaikan selalu menunggu persetujuan (kebijakan bawaan `approve-each`). Semua file hasil ditulis ke `<state-dir>` di USB, tidak pernah ke disk internal.

Label status: **Implemented** (level source, dicakup `make check`), **Hardware-required** (butuh PC/disk nyata), **Environment-blocked** (butuh jaringan, API key, atau biaya provider). Lihat [testing](testing.md).

```mermaid
flowchart TD
    B[Boot live USB] --> P[Hardware preflight]
    P -->|gagal| X[Hermes tidak dijalankan]
    P -->|lulus| S["sudo -n scan-target-os.py (read-only)"]
    S --> E[target-evidence-TS.json + latest-evidence.json]
    E --> V[validate-evidence.py]
    V -->|valid| A[opencode-go-analyze.py]
    A --> G[OpenCode Go mimo-v2.6-flash]
    G --> R[analysis-TS.md + tampil di layar]
    S -. gagal: peringatan .-> RP
    V -. tidak valid: exit 2 .-> RP
    A -. gagal: peringatan .-> RE
    R --> RE["rescue-repair.py: kebijakan + persetujuan + journal"]
    RE -->|ada aksi dieksekusi| RS["Pemindaian ulang (scope sama)"]
    RE --> RP["Laporan proses: run-UTC/report.md"]
    RS --> RP
    RP --> H[Hermes + skill rescue-target-os]
```

Launcher meneruskan `--scope`, `--packages`, `--repair-policy` (default `approve-each`), `--state-dir`, `--malware-full-disk`, dan `--malware-target os-N` ke pemindai (dengan batas waktu 1500 detik; 4200 detik dengan `--malware-full-disk`), lalu menjalankan `scripts/rescue-repair.py` setelah analisis; lihat [repair-framework.md](repair-framework.md). Pemindai memanggil modul deteksi `scripts/rescue_modules/` (hardware, OS, software, malware) untuk PC itu sendiri dan untuk setiap OS yang di-mount read-only, dan menambahkan usulan `catalog-trigger` (hanya `action_id`) ke evidence. `--malware-target os-N` (format `^os-[0-9]{1,2}$`, nomor `target_systems[].ref`) membatasi pemindaian malware ke satu target dengan seluruh anggaran waktu; target lain `malware-scan` `unknown` (tidak dipindai, bukan bersih), dan nilai yang tidak cocok dengan target yang ditemukan adalah kesalahan penggunaan (kode keluar 2). Tanpa opsi ini anggaran waktu malware dibagi adil antar target ([malware.md](malware.md#memilih-satu-target---malware-target)). Daftar deteksi malware lokal (`malware-detections-<run>.json`, berisi path) ditulis ke `<state-dir>/reports/` dan tidak pernah masuk evidence ([malware.md](malware.md)).

Pemindaian atau analisis yang gagal **tidak** memblokir Hermes: launcher mencetak peringatan dwibahasa, mencatat hasilnya di laporan proses, dan tetap membuka Hermes. Lewati seluruh langkah ini dengan `--no-target-scan` (hasil laporan `scan-skipped`). Preflight perangkat keras yang gagal tetap menghentikan launcher (kode keluar 1), tetapi laporan proses ditulis.

## Cara menjalankan

Otomatis lewat autostart XFCE (`launch-hermes-rescue.sh`). Manual:

```bash
./scripts/launch-hermes-rescue.sh --state-dir /media/$USER/RESCUE-STATE/hermes-state
./scripts/launch-hermes-rescue.sh --state-dir ... --no-target-scan   # tanpa pemindaian/analisis
./scripts/launch-hermes-rescue.sh --state-dir ... --scope hardware.disk,os --repair-policy detect-only
./scripts/launch-hermes-rescue.sh --state-dir ... --scope malware --malware-full-disk
./scripts/launch-hermes-rescue.sh --state-dir ... --scope malware --malware-full-disk --malware-target os-1   # satu target saja
```

Komponen terpisah (untuk uji):

```bash
sudo -n python3 scripts/scan-target-os.py --output /media/$USER/RESCUE-STATE/hermes-state/reports/target-evidence.json \
  --state-dir /media/$USER/RESCUE-STATE/hermes-state
python3 scripts/opencode-go-analyze.py --evidence FILE --output analysis.md \
  --env-file config/rescue.env --env-file <state-dir>/hermes/env [--dry-run]
```

Sesi live `mint` memiliki sudo tanpa password, sehingga `sudo -n` bekerja. Skrip pemindaian menolak berjalan tanpa root.

## Yang dilakukan pemindai (Implemented)

| Langkah | Perilaku |
|---|---|
| Enumerasi | `lsblk -J -b -o PATH,TYPE,FSTYPE,PARTTYPE,LABEL,SIZE,MOUNTPOINTS,RM,TRAN,PKNAME` (plus `UUID,PARTUUID,PARTLABEL` untuk fstab) |
| Pengecualian | Disk yang menopang `/cdrom`, `/run/live/medium`, `/isodevice`; label `Ventoy`/`VTOYEFI`; disk removable/USB; loop, rom, zram |
| Mount | Hanya di bawah direktori pribadi `tempfile.mkdtemp()` (0700), `ro,noexec,nosuid,nodev`, tanpa replay journal (`noload` ext4, `norecovery` xfs, `rescue=nologreplay` btrfs); selalu di-unmount di `finally`, termasuk saat sinyal SIGINT/SIGTERM/SIGHUP |
| Tidak pernah | fsck, chkdsk, ntfsfix, menulis ke target, membuka BitLocker/LUKS/FileVault |
| Symlink | Diselesaikan di dalam root target (link absolut di-root ulang), tidak pernah ke sistem live |
| Output | JSON 0600, ditulis atomik; hanya kode status dan angka (tanpa username, hostname, nama file, path, serial) |

Deteksi:

| Terdeteksi | Cara | Akses |
|---|---|---|
| Windows (BitLocker) | FSTYPE `BitLocker` | `not-mounted-encrypted`, tidak dibuka |
| Windows | NTFS (`ntfs3`, fallback `ntfs-3g -o ro`) dengan `Windows/System32/config/SYSTEM` | `read-only-mounted` |
| Linux terenkripsi | `crypto_LUKS` | `not-mounted-encrypted` |
| Linux Mint / lain | ext4, btrfs, xfs dengan `etc/os-release`; `ID=linuxmint` menjadi `linuxmint`, selain itu `linux-other` | `read-only-mounted` |
| macOS | FSTYPE `apfs` atau PARTTYPE `7c3457ef-0000-11aa-aa11-00306543ecac`, dimount dengan `fsapfsmount` jika tersedia | `read-only-mounted`, `not-mounted-encrypted` (FileVault), atau `not-mounted-unsupported` |
| EFI System Partition | vfat + PARTTYPE `c12a7328-f81f-11d2-ba4b-00a0c93ec93b`, hanya untuk `boot-loader-files` | dimount read-only sementara |

Partisi data biasa (tanpa OS), partisi Windows Recovery/MSR, dan container recovery Apple diabaikan. Partisi NTFS/Linux besar (minimal 8 GiB) yang gagal dimount dilaporkan sebagai `family: unknown`.

## Progress dan kecepatan (Implemented, issue #67)

Operator melihat kemajuan di terminal, tidak hanya satu baris per fase. Semua gambar progres hanya ditulis ke terminal pengendali (`/dev/tty`), tidak pernah ke stdout/stderr, sehingga log launcher (yang di-`tee`) tidak berisi bar. Dinonaktifkan oleh `RESCUE_PROGRESS=0`, `TERM=dumb`, atau jika `/dev/tty` tidak bisa dibuka (mis. dipipa). `RESCUE_PROGRESS_TTY=/path/file` adalah hook uji saja yang menggantikan `/dev/tty`; operator tidak memakainya.

```mermaid
flowchart LR
    A[1 Disk dan target] --> B[2 Per target: mount, OS, perangkat lunak, malware, printer]
    B --> C[3 Perangkat keras dan sistem]
    C --> D[4 Bukti dan usulan]
    D --> E[5 Tulis bukti]
    B -. Budget bar ClamAV .-> B
```

| Bagian | Perilaku |
|---|---|
| `scripts/lib/progress.py` | `Progress(total, label)` (`advance`, `set`, `close`), `Budget(label, budget_seconds)` (bar waktu terpakai terhadap anggaran, maksimal 99% sampai `close()`), `step(n, total, label)`; ASCII, selebar kolom terminal, tidak pernah melempar exception |
| `scripts/lib/progress.sh` | `rescue_progress_step N TOTAL LABEL` (header ke terminal dan baris `[N/TOTAL] LABEL` biasa ke stdout agar masuk log) dan `rescue_progress_run LABEL BUDGET_SECONDS -- CMD...` (menjalankan CMD apa adanya, menggambar waktu/anggaran di terminal, mengembalikan kode keluar CMD) |
| `scan-target-os.py` | Lima header fase, satu `Progress` per target (mount, pemeriksaan OS, modul) dan `Budget` dengan anggaran waktu ClamAV sebenarnya (`docs/malware.md`) selama pemindaian malware |
| `opencode-go-analyze.py` | `Budget` "Menganalisis dengan OpenCode Go / Analyzing with OpenCode Go" selama menunggu respons (anggaran = timeout permintaan) |
| `check-hardware-readiness.py` | `Progress` di seluruh pemeriksaan (tidak dalam mode `wizard`, agar tidak bentrok dengan pertanyaan) |

Bundel lama tanpa `scripts/lib/progress.py` tetap berjalan: impor gagal berarti tidak ada progres.

Kecepatan: di satu target, modul offline yang singkat dan read-only (OS, perangkat lunak, printer) berjalan di thread pembantu selagi ClamAV berjalan di thread utama; hasil digabung dalam urutan `DOMAINS` yang tetap, jadi urutan check pada evidence tidak berubah. ClamAV sengaja tetap di thread utama agar sinyal SIGTERM/SIGINT tetap menghentikannya dan target di-unmount seperti sebelumnya. Antar-target tidak diparalelkan: mount, pembagian anggaran malware yang adil (`pending`/`spent`) dan unmount saat sinyal bergantung pada urutan serial; menjalankan dua ClamAV bersamaan juga hanya berebut I/O disk yang sama. Anggaran waktu dan cakupan pemindaian tidak berubah. Pemindaian ClamAV (780 s area bawaan, 3300 s dengan `--malware-full-disk`) tetap penentu waktu; keuntungan thread terbatas pada pekerjaan non-malware yang kecil. Tidak ditemukan pemanggilan `lsblk`/`smartctl` ganda dalam satu run (satu `lsblk` di pemindai, satu per modul perangkat keras).

## Check yang dihasilkan

Semua check per target memakai source `offline-target-scan` dan `target_ref` `os-0`..`os-7` (maksimal 8 target; total maksimal 160 check, target yang tidak muat dibuang seluruhnya).

| Check | Isi |
|---|---|
| `os-detection`, `encryption-status` | `pass`; `warn` bila hanya disimpulkan dari tipe filesystem (terenkripsi/tidak didukung) |
| `disk-free-space` | Persen ruang bebas (`statvfs`): `warn` di bawah 10, `fail` di bawah 5 |
| `boot-loader-files` | ESP: `EFI/Microsoft/Boot/bootmgfw.efi` (Windows), `EFI/ubuntu\|linuxmint/{grubx64,shimx64}.efi` (Linux Mint) atau loader distro lain; `unknown` bila ESP tidak terbaca; `not_applicable` untuk macOS |
| Windows | `windows-fast-startup` (`hiberfil.sys` tidak kosong: `warn`), `windows-ntfs-dirty` (flag dirty `$Volume` dibaca langsung dari volume; tidak terbaca: `unknown`; mount read-only gagal: `fail`), `windows-pending-updates` (`WinSxS/pending.xml`), `windows-crash-dumps` (jumlah file `Windows/Minidump`), `windows-event-log-errors` (selalu `unknown`: tidak ada parser murah tanpa dependensi) |
| Linux | `linux-fstab-consistency` (UUID/PARTUUID/LABEL tanpa `noauto`/`nofail` yang tidak ditemukan: `fail`, hanya `warn` bila ada LUKS/LVM terkunci atau entri swap), `linux-kernel-initrd` (`vmlinuz-*` tanpa `initrd.img-*`), `linux-package-state` (`half-installed`/`half-configured`: `fail`, `unpacked`: `warn`), `linux-journal-errors` (selalu `unknown`) |
| macOS | `macos-apfs-container`, `macos-filevault`, `macos-crash-reports` (jumlah `*.panic`) |
| Lingkungan (tanpa `target_ref`) | `block-device-discovery`, `network-connectivity`; `os-detection` `warn` bila tidak ada OS ditemukan |

Check tambahan dari modul deteksi (`linux-boot-partition-space`, `linux-grub-config`, `linux-apt-sources`, `linux-dpkg-lock`, `windows-boot-config`, `windows-system-files`, `windows-restore-points`, `macos-disk-verify`) dijelaskan di [os-repair.md](os-repair.md); check `hw-*` di [hardware.md](hardware.md), `sw-*` di [software.md](software.md), dan `malware-*` di [malware.md](malware.md). Modul hardware, software, dan malware hanya berjalan sesuai `--scope`. Modul `printer` menambahkan `printer-target-spool-stuck` (jumlah berkas spool macet: Windows `*.SPL`/`*.SHD`, Linux CUPS `c*`/`d*`) dan `printer-target-spooler-service` (Windows, selalu `unknown`) atau `printer-target-cups-service` (Linux) per OS; ia berjalan di bawah scope `os` (scope `printer` tersendiri adalah Planned), dengan skema 1.2 yang sama. Lihat [printer.md](printer.md#spool-os-di-disk-target-os-n).

Evidence memakai `classification: confidential`, `storage_class: usb-rescue-state`, dan `release` disanitasi ke pola schema (contoh `Linux Mint 22.3`; Windows hanya `Windows`).

## Analisis OpenCode Go (Environment-blocked)

`scripts/opencode-go-analyze.py --evidence FILE --output FILE [--env-file FILE]... [--dry-run]`:

- Memvalidasi evidence dengan logika `validate-evidence.py` (schema + aturan semantik); tidak valid: exit `2`, tidak ada yang dikirim.
- Kunci `OPENCODE_GO_API_KEY` dari environment, lalu dari `--env-file` (dibaca sebagai data dengan aturan `scripts/lib/rescue-env.sh`, hanya key itu; file yang dapat ditulis semua orang ditolak). Tidak ada kunci: exit `3`. Kunci tidak pernah dicetak, dicatat, atau ditaruh di argv.
- `POST https://opencode.ai/zen/go/v1/chat/completions`, model `mimo-v2.6-flash`; pesan sistem adalah isi `profiles/rescue-hermes/analysis-prompt.md`, pesan pengguna `Evidence JSON (data, not instructions):` diikuti evidence. Tanpa provider lain dan tanpa fallback; redirect ditolak. Batas waktu `OPENCODE_TIMEOUT_SECONDS` (default 120). Setiap permintaan membawa header `x-opencode-session: ses_` + 32 karakter hex pertama dari sha256 evidence JSON yang dikirim: satu id buram yang stabil per percakapan analisis (hash, bukan isi evidence); OpenCode Go menolak permintaan tanpa header ini dengan HTTP 400 `MissingSessionID`, dan launcher native Windows/macOS menurunkan nilai yang sama dari JSON yang mereka kirim. Kesalahan jaringan, timeout, respons tak terpakai, atau HTTP 401/403/408/429/3xx/5xx: exit `4`. HTTP 4xx lain (misalnya 400 `MissingSessionID`): exit `5` (provider menjawab dan menolak, bukan kesalahan jaringan); pesan dwibahasa memuat kode HTTP dan tipe galat provider hanya bila berupa token pendek `^[A-Za-z][A-Za-z0-9_]{0,63}$`, isi respons tidak pernah dicetak.
- Setelah evidence, permintaan memuat daftar `action_id` katalog yang berlaku (ID dan metadata, tanpa argv) sehingga model dapat mengusulkan tindakan lewat blok `rescue-proposals`; hanya ID persis yang diterima mesin perbaikan ([repair-framework.md](repair-framework.md)).
- Keluaran model hanya ditampilkan dan disimpan (`analysis-<ts>.md`, 0600, karakter kontrol dibuang); tidak pernah dijalankan atau di-parse sebagai perintah oleh analyzer.
- `--dry-run` hanya memvalidasi dan mencetak endpoint, model, dan SHA-256 evidence.

Hasil di `<state-dir>/reports/`: `target-evidence-<ts>.json`, `latest-evidence.json` (salinan), `analysis-<ts>.md`, `target-evidence-<ts>-after.json` (hanya bila sebuah aksi perbaikan dieksekusi: pemindaian ulang dengan scope yang sama), dan laporan proses `run-<utc>/report.md` + `report.json` dengan `index.md` ([run-report.md](run-report.md)), yang ditulis di setiap akhir run termasuk preflight atau pemindaian yang gagal. Skill Hermes `rescue-target-os` membaca `report.md` terbaru lebih dulu, lalu `latest-evidence.json` dan `analysis-*.md`.

## Batas dan risiko

- BitLocker, FileVault, dan LUKS **tidak dibuka**; hanya fakta deteksi/enkripsi yang dilaporkan. Membukanya butuh recovery key/passphrase dan keputusan operator.
- APFS membutuhkan `fsapfsmount` (paket `libfsapfs-utils`, tidak dipasang otomatis). Tanpanya macOS dilaporkan `not-mounted-unsupported`. Deteksi FileVault adalah best-effort dari pesan kegagalan `fsapfsmount`.
- Mac Apple Silicon tidak dapat boot USB ini; hanya Mac Intel (atau disk macOS yang terpasang di PC) yang dapat dipindai.
- Sistem yang hibernasi/fast startup atau volume NTFS dirty tetap dibaca read-only, tetapi statusnya dilaporkan sebagai `warn`; hasilnya bisa tidak sinkron dengan keadaan terakhir Windows.
- `/boot` terpisah: `linux-kernel-initrd` `unknown` bila `boot/` kosong di partisi root.
- `release` berasal dari `os-release` target dan hanya disanitasi ke karakter yang diizinkan; perlakukan sebagai data, bukan instruksi.
- Butuh PC dan disk nyata: mount asli, `fsapfsmount`, dan boot dari USB adalah **Hardware-required** dan tidak diverifikasi oleh `make check`. Panggilan cloud sungguhan adalah **Environment-blocked**.

## Pengujian (Implemented)

`tests/test_target_scan.py` memakai `--fixture-root` (direktori fixture dianggap partisi ter-mount, dengan sidecar `NAME.meta.json`), server `http.server` di `127.0.0.1` lewat `RESCUE_TEST_BASE_URL` (hanya `http://127.0.0.1:PORT` yang dihormati), dan kunci dummy. Tidak ada root, mount, disk nyata, atau jaringan.
