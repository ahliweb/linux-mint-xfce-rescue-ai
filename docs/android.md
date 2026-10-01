# Android (ponsel/tablet via USB)

> Managed by **ahlikoding.com** and **satpamsiber.com** from **ahliweb.com**.

Perangkat Android (smartphone atau tablet) yang dicolok lewat USB ke PC yang menjalankan USB rescue dapat menjadi **target** pemeriksaan: toolkit mendaftar semua perangkat USB, menunjukkan **port USB** mana yang dipakai ponsel (dan mana yang USB rescue itu sendiri), lalu menjalankan pemeriksaan ADB **read-only** bila USB debugging aktif dan disetujui. Sejak fase 2 ada tiga **tindakan perbaikan** katalog yang aman atau dapat dibalik, dijalankan hanya oleh mesin perbaikan ([di bawah](#tindakan-perbaikan-fase-2)), dan sejak #52 ada [flashing dan unbrick](#flashing-dan-unbrick-52) yang dipanggil operator. Isu: ahliweb/linux-mint-xfce-rescue-ai#48 dan #52. Label status: **Implemented** (level source, dicakup `make check`), **Planned**, **Hardware-required** (butuh PC dan ponsel nyata), **Environment-blocked**. Lihat [testing](testing.md).

## Lingkup

| Bagian | Status |
|---|---|
| Inventaris USB read-only dari sysfs (tanpa kerja sama ponsel): port, kecepatan, lokasi fisik ACPI, penanda hub dan USB rescue, kelas, merek, mode Android | Implemented |
| Target keluarga `android` (`and-N`) dengan id opak (hash berkunci, bukan serial) di evidence schema 1.3 | Implemented |
| Pemeriksaan ADB read-only (versi, patch, verified boot, SELinux, penyimpanan, baterai, indikator root, admin perangkat, aksesibilitas, aplikasi non-store, Play Protect) | Implemented |
| Tindakan perbaikan katalog Android (`rescue-ai/v1/catalog/android.json`: `android.trim-caches`, `android.enable-package-verifier`, `android.reboot`), parameter `android_device` yang di-resolve mesin, penawaran pemindaian di launcher live | Implemented (fase 2) |
| Fastboot: ganti slot A/B (`reversible`), flash image zip resmi atau partisi dalam allowlist (`destructive`), reboot; status kunci bootloader, slot, fastbootd dibaca read-only ([flashing](#flashing-dan-unbrick-52)) | Implemented (#52); fastboot dan ponsel nyata Hardware-required |
| Samsung mode Download lewat Heimdall (`heimdall-flash`) | **EKSPERIMENTAL** (#52); Hardware-required |
| Qualcomm EDL (9008) dan MediaTek BROM/preloader | **Hanya deteksi dan panduan** ke pusat servis resmi; tanpa alat pip, programmer firehose, atau exploit BROM |
| Membuka atau mengunci bootloader, root, factory reset, `erase`, `-w`, install/uninstall APK, `adb sideload`, `reboot bootloader/recovery`, partisi bootloader/radio/modem/persist/efs/frp | **Tidak pernah**: tidak ada di katalog dan validator katalog menolaknya |
| Uji dengan ponsel dan PC nyata (port fisik, prompt RSA, ACPI `_PLD` asli) | Hardware-required |

```mermaid
flowchart TD
    U["Ponsel dicolok lewat USB"] --> I["scan-android.py: baca /sys/bus/usb/devices (read-only)"]
    I --> T["Tabel semua perangkat USB: port, lokasi, kecepatan, mode, USB RESCUE, HUB"]
    I --> M{"Ada antarmuka ADB?"}
    M -- tidak --> O["access: usb-only, check android-* unknown"]
    M -- ya --> A{"adb devices -l"}
    A -- unauthorized --> H["Operator menyetujui prompt RSA di ponsel, lalu pindai ulang"]
    A -- "device" --> C["Pemeriksaan ADB read-only dengan argv tetap"]
    C --> E["Evidence 1.3: and-N, usb_ports, checks"]
    O --> E
    E --> V["Validasi schema sebelum ditulis"]
    V --> R["Analisis + skill Hermes rescue-android"]
    V --> G["rescue-repair.py: usulan dari katalog android.json"]
    G --> D["android_device: cari ulang ponsel (USB + adb), opaque id harus sama"]
    D --> J["Persetujuan, adb -t ID, verify, journal"]
```

## Mode koneksi yang didukung

Mode dikenali hanya dari pasangan `vendor:product` dan triplet kelas/subkelas/protokol antarmuka USB (tidak ada string yang dibaca).

| Mode (`android_mode`) | Dikenali dari | Catatan |
|---|---|---|
| `adb` | antarmuka `ff/42/01` | USB debugging aktif (belum tentu disetujui). Recovery dan sideload juga tampil sebagai `adb`: tidak dapat dibedakan dengan andal |
| `fastboot` | antarmuka `ff/42/03` | Bootloader; hanya dideteksi |
| `mtp-ptp` | antarmuka `06/01/01` | MTP dan PTP memakai triplet yang sama; dilaporkan jujur sebagai `mtp-ptp`. Dianggap ponsel hanya bila vendornya ada di tabel merek (kamera dengan PTP tidak dianggap ponsel) |
| `rndis` | `e0/01/03` atau `ef/04/01` | Tethering USB. Tidak pernah cukup untuk menyebut perangkat sebagai Android (modem LTE juga memakainya) |
| `qualcomm-edl` | `05c6:9008` | Emergency Download; biasanya ponsel mati total atau sengaja dimasukkan ke EDL |
| `mediatek-brom` | `0e8d:2000` (preloader), `0e8d:0003` (BROM) | Preloader juga muncul beberapa detik pada setiap start normal ponsel MediaTek |
| `samsung-download` | `04e8:685d` | Download/Odin |
| `spreadtrum-download` | `1782:4d00` | Unisoc/Spreadtrum download |
| `none` | selain di atas | Perangkat USB biasa |

**Ponsel yang hanya mengisi daya tidak terlihat sama sekali.** Kabel charge-only (tanpa jalur data), port yang hanya menyuplai daya, atau ponsel dengan "Hanya mengisi daya" tidak menampilkan perangkat USB; tidak ada alat USB yang dapat mendeteksinya. Telepon dengan MTP vendor-spesifik (`ff/ff/00`, hanya dikenali lewat string deskriptor) tanpa ADB juga tidak dikenali sebagai Android karena toolkit tidak membaca string. Merek berasal dari tabel `vendor ID` kecil (Google, Samsung, Xiaomi, OPPO/Realme, vivo, Huawei, Motorola, LG, Sony, OnePlus, Qualcomm, MediaTek, Lenovo, ASUS, ZTE, HTC, HMD/Nokia, Unisoc, Meizu); lainnya `other`. Satu ID dapat dipakai beberapa merek, jadi merek hanyalah petunjuk.

## Identifikasi port USB

`python3 scripts/scan-android.py --list-usb` mencetak tabel dwibahasa semua perangkat USB (tanpa root, tanpa jaringan):

| Kolom | Sumber |
|---|---|
| PORT | nama entri `/sys/bus/usb/devices/<bus>-<port>[.<port>]*` (pola `^[0-9]{1,3}-[0-9]{1,3}(\.[0-9]{1,3}){0,6}$`; antarmuka `N-N:C.I` dan root hub `usbN` dilewati) |
| KECEPATAN, USB | `speed` (Mbps: 1.5, 12, 480, 5000, ...) dan `version` |
| LOKASI | `<dev>/port/physical_location/{panel,horizontal_position,vertical_position}` dan `port/connect_type` bila firmware (ACPI `_PLD`) menyediakannya; `internal` untuk perangkat `hardwired`; `-` bila tidak ada data (banyak PC tidak mengisinya) |
| KELAS | `bDeviceClass` dan kelas antarmuka (`mass-storage`, `hid`, `hub`, `vendor-specific`, ...) |
| MEREK, MODE ANDROID | tabel vendor ID dan triplet antarmuka (di atas) |
| TANDA | `[USB RESCUE]`, `[HUB]`, dan `[and-N]` untuk target Android |

Kedalaman hub (`hub_depth`) adalah jumlah hub di antara root hub dan perangkat (`3-2.1` ada di belakang satu hub). USB rescue ditandai `[USB RESCUE]` bila perangkat itu menopang medium live (mount `/cdrom`, `/run/live/medium`, atau `/isodevice` dari `/proc/self/mountinfo`; tumpukan device-mapper Ventoy diikuti sampai disk di bawahnya) atau partisi berlabel `Ventoy`/`VTOYEFI` (`/dev/disk/by-label`). Hanya dibaca; tidak ada perintah yang dijalankan. Contoh keluaran:

```
Ponsel and-0 terdeteksi di port 3-2.1 (panel kiri, sisi kiri, 480 Mbps), merek samsung, mode ADB.
(Phone and-0 detected on port 3-2.1 (left panel, left side, 480 Mbps), brand samsung, mode ADB.)
```

Bila tidak ada ponsel, tabel diikuti petunjuk: kabel charge-only, pilih "Transfer file (MTP)", aktifkan Opsi pengembang (Pengaturan > Tentang ponsel > ketuk Nomor build 7 kali) lalu USB debugging, colok langsung tanpa hub. Layar operator boleh menampilkan **merek dan port**, tidak pernah serial.

## Alur otorisasi ADB

1. Ponsel: aktifkan Opsi pengembang dan **USB debugging**, colok kabel data, buka kunci layar.
2. `scan-android.py` memanggil `adb devices -l`. Status `unauthorized` berarti ponsel belum menerima komputer ini: ponsel menampilkan prompt "Izinkan USB debugging?" (sidik jari kunci RSA). Operator menyetujuinya (opsional "Selalu izinkan dari komputer ini"), lalu pindai ulang. Kunci ADB tinggal di `~/.android` sesi live (volatil) sehingga prompt muncul lagi di sesi berikutnya; USB debugging sebaiknya dimatikan setelah perbaikan.
3. Setiap perangkat dialamatkan dengan `adb -t <transport_id>` (bilangan bulat dari `adb devices -l`), sehingga serial tidak pernah masuk argv yang kita bentuk. Setiap perintah adalah tuple argv tetap, dengan batas waktu 20 detik, `stdin` dari `/dev/null`, keluaran dibaca paling banyak 4 MiB, dan penemuan mDNS dimatikan (`ADB_MDNS=0`). `adb` memakai server localhost `127.0.0.1:5037`; pada sesi live server yang dimulai pemindaian dihentikan (`adb kill-server`) di akhir, di mode host server milik operator dibiarkan.
4. Status ADB lain (`offline`, `recovery`, `sideload`, `bootloader`, `no permissions`) menghasilkan `access: adb-unavailable` dan check `unknown`. Paket `adb` dan aturan udev (`android-sdk-platform-tools-common`) disediakan oleh [persistence](persistence.md); tanpa `adb` check ADB `unknown`.

Pemindaian tidak pernah menjalankan perintah yang menulis: `adb root`, `install`, `push`, `pull`, `sideload`, `reboot`, `unlock`, `fastboot flash`, string shell yang dibentuk dari data, atau perintah dari keluaran model. Satu-satunya perintah yang mengubah ponsel adalah tiga tindakan katalog di bawah, dengan persetujuan operator.

## Check yang dihasilkan

Check lingkungan (tanpa `target_ref`): `usb-device-count` (angka perangkat non-hub; `pass`) dan `usb-android-device-count` (angka perangkat Android; `warn` bila 0). Check per target memakai source `collector-allowlist` dan `target_ref` `and-0`..`and-7` (urutan menurut port, jadi nomor stabil selama ponsel tidak dipindah). Hanya status dan angka terbatas; `unknown` bila nilai tidak terbaca, dan semua check turunan ADB `unknown` bila `access` bukan `adb-authorized`.

| Check | Nilai | Status |
|---|---|---|
| `android-connection-mode` | - | `pass`: ADB disetujui. `warn`: `unauthorized`/`offline`/`recovery`/`sideload`/`bootloader`, mode tingkat rendah (fastboot, EDL, download), atau terlihat di USB tanpa ADB. `unknown`: `adb` tidak ada dan mode butuh ADB |
| `android-os-version` | `count` = API level (SDK) | `pass` 33+, `warn` 29-32, `fail` di bawah 29 |
| `android-security-patch-age` | `days` sejak `ro.build.version.security_patch` | `pass` sampai 90, `warn` di atas 90, `fail` di atas 365 (memakai jam PC; tanggal patch di masa depan dihitung 0) |
| `android-verified-boot` | - | `ro.boot.verifiedbootstate`: `green` `pass`, `yellow`/`orange` `warn`, `red` `fail` |
| `android-bootloader-lock` | - | `ro.boot.flash.locked`/`ro.boot.vbmeta.device_state`: terkunci `pass`, tidak terkunci `warn` |
| `android-selinux` | - | `getenforce`: `Enforcing` `pass`; `Permissive`/`Disabled` `fail` |
| `android-storage-free` | `percent` bebas di `/data` (`df /data`) | `warn` di bawah 10, `fail` di bawah 3 |
| `android-battery-level` | `percent` | `warn` di bawah 20, `fail` di bawah 10, kecuali sedang mengisi (`pass`) |
| `android-battery-health` | - | kode `dumpsys battery`: 2 baik `pass`; 3 panas berlebih, 4 mati, 5 tegangan berlebih `fail`; 6 gagal tak ditentukan, 7 dingin `warn` |
| `android-battery-temperature` | `celsius` bulat | `warn` 40 ke atas, `fail` 45 ke atas; di bawah 0 `warn` tanpa angka |
| `android-root-indicators` | - | `warn` bila `su` ada di jalur standar (`which su`, `ls -d` pada jalur tetap) atau `ro.debuggable=1`; `pass` hanya berarti tidak ada indikator standar (root dapat disembunyikan) |
| `android-device-admin-count` | `count` admin perangkat aktif | `pass` 0-2, `warn` 3 ke atas (jumlah saja, tanpa nama) |
| `android-accessibility-services-count` | `count` layanan aksesibilitas aktif | `warn` bila lebih dari 0 (jalur umum adware/malware; jumlah saja) |
| `android-unknown-sources-count` | `count` paket pihak ketiga yang tidak dipasang oleh toko (installer `null`, `adb`, atau pemasang paket) | `warn` bila lebih dari 0 (nama paket tidak pernah dikeluarkan) |
| `android-play-protect` | - | `warn` bila `package_verifier_user_consent=-1` atau `package_verifier_enable=0`; `pass` bila disetujui; `unknown` bila tidak ada (misalnya tanpa layanan Google) |
| `android-developer-options` | - | `not_applicable` (`development_settings_enabled=1`): wajib aktif agar pemindaian ini dapat berjalan, bukan temuan; `pass` bila 0 |
| `android-usb-port-speed` | - | `warn` bila ponsel bernegosiasi di bawah 480 Mbps (kabel atau port bermasalah); `unknown` bila port tidak diketahui |

Ambang di atas adalah heuristik dan hanya bergantung pada angka; hasil `pass` bukan bukti ponsel sehat atau bersih dari malware.

## Evidence schema 1.3

- `target_systems[]`: `family: android`, `ref: and-N`, `detection: usb-adb | usb-enumerated`, `access: adb-authorized | adb-unauthorized | adb-unavailable | usb-only`, `release: Android 14` (angka versi saja), `architecture`, `encryption: unknown`, plus `opaque_id` dan `usb_port`.
- `usb_ports[]` (maks. 64): `port`, `speed_mbps`, `usb_version`, `hub_depth`, `is_hub`, `is_boot_media`, `android_mode`, `android_modes`, `vendor_brand` (enum tertutup), `panel`, `horizontal_position`. Tanpa string bebas, `vendor:product`, atau serial; `additionalProperties: false`.
- Check ID baru: 17 `android-*` ditambah `usb-device-count` dan `usb-android-device-count`; sejak #52 lima lagi hanya untuk ponsel dalam mode tingkat rendah (`android-fastboot-lock-state`, `android-fastboot-slot`, `android-fastboot-userspace`, `android-heimdall-detect`, `android-low-level-mode`, lihat [flashing](#flashing-dan-unbrick-52)). Jenis nilai tidak bertambah (`count`, `percent`, `days`, `celsius`).
- `target_device_opaque_id` adalah `opaque_id` ponsel bila tepat satu target Android, selain itu id mesin seperti kolektor lain. Skema 1.0-1.2 menolak semua bidang 1.3 (aturan semantik `scripts/validate-evidence.py`).
- Fixture: `rescue-ai/v1/fixtures/valid-android-usb.json`, `invalid-android-serial.json` (serial diselundupkan ke `usb_ports`), `invalid-1.3-fields-in-1.2.json`.

## Privasi

| Data | Perlakuan |
|---|---|
| Serial USB (= serial Android), string pabrikan/produk, nama akun, nama paket, nomor telepon, IMEI, alamat MAC Wi-Fi/Bluetooth | **Tidak pernah** masuk evidence, laporan, journal, permintaan analyzer, issue, skill, atau layar. Hanya properti `ro.*` dalam allowlist, hitungan, dan angka terbatas yang dipertahankan; sisanya dibuang saat diurai |
| Identitas target | `opaque_id` = `target-` + 16 hex pertama HMAC-SHA256 serial dengan kunci dari `/etc/machine-id` mesin (tidak pernah dikeluarkan). Serial tebakan tidak dapat dicocokkan dari evidence; id stabil untuk ponsel yang sama di PC yang sama sehingga pemindaian sebelum/sesudah dapat dibandingkan. Tanpa serial dipakai port dan `vendor:product` |
| `vendor:product` | Tidak ada di evidence; hanya `vendor_brand` dari enum tertutup |
| Layar operator | Merek dan port boleh, serial tidak |
| Keluaran `adb` | Data tak tepercaya: diurai ke himpunan status tertutup dan angka terbatas lalu dibuang |

## Model ancaman dan batas

Ponsel adalah peer USB yang tidak tepercaya: ia dapat menjawab perintah dengan data sembarang, keluaran tak terbatas, atau tidak menjawab. Karena itu semua panggilan memakai batas waktu dan batas ukuran, keluaran tidak pernah dijadikan perintah, dan hasil hanya status tertutup. Lihat [security-model](security-model.md).

- Butuh ponsel dan PC nyata: aturan udev, prompt RSA, ACPI `_PLD`, dan berbagai versi `adb` adalah **Hardware-required** dan tidak diverifikasi `make check` (uji memakai pohon sysfs palsu dan `adb` palsu).
- Android sebelum 8 atau ROM khusus dapat mengubah format `dumpsys`/`pm`; bidang yang tidak terbaca menjadi `unknown`.
- Enkripsi tidak dilaporkan (`encryption: unknown`); pemindaian tidak membuka kunci layar dan tidak mengakses data pengguna.
- Perangkat tanpa data USB (hanya mengisi daya) dan MTP vendor-spesifik tanpa ADB tidak terdeteksi.
- Keluaran model tidak pernah dijalankan; skill Hermes [`rescue-android`](../profiles/rescue-hermes/skills/rescue-android/SKILL.md) memandu diagnosis dan hanya boleh mengusulkan `action_id` katalog Android; ia melarang flashing, unlock, root, factory reset, pemasangan APK, dan pencetakan serial.

## Tindakan perbaikan (fase 2)

Tindakan Android hanyalah **aksi katalog bertipe** di `rescue-ai/v1/catalog/android.json` (domain `android`, prefix `android.`, scope `android`, `target_families: ["android"]`, platform `live-linux` dan `linux-host`), dijalankan oleh `scripts/rescue-repair.py` dengan kontrak yang sama seperti domain lain ([repair-framework](repair-framework.md)): `approve-each` default, `auto-safe` hanya untuk aksi `safe` yang dipicu katalog, setiap aksi di-verify dan dicatat di journal. Argv selalu tetap; AI hanya dapat menyebut `action_id` dan `target_ref` (`and-N`).

| Aksi | Risiko | Pemicu | Argv (ringkas) | Verify | Rollback |
|---|---|---|---|---|---|
| `android.trim-caches` | `safe` | `android-storage-free` warn atau fail | `adb -t ID shell pm trim-caches 999G` | `adb -t ID shell df /data` (kode keluar 0) | tidak ada |
| `android.enable-package-verifier` | `reversible` | `android-play-protect` warn | `adb -t ID shell settings put global package_verifier_enable 1` | `adb -t ID shell settings get global package_verifier_enable` harus mencetak baris `1` (`expect_line`) | otomatis: `settings delete global package_verifier_enable` |
| `android.reboot` | `safe` | tanpa pemicu: hanya `--select` | `adb -t ID reboot` | `adb -t ID get-state` setelah mesin menunggu ponsel kembali | tidak ada |

<a id="android-trim-caches"></a>
**`android.trim-caches`.** Meminta Android membebaskan cache semua aplikasi sampai ruang kosong yang diminta (`999G` berarti "sebanyak mungkin"). Data pengguna, akun, dan aplikasi tidak disentuh; aplikasi hanya membangun ulang cache-nya. Satu-satunya aksi yang boleh jalan otomatis di `auto-safe` (bila `android-storage-free` warn/fail). Verify hanya membuktikan ponsel masih menjawab dan `df /data` berjalan (kode keluar 0), jadi **tidak** membuktikan ruang bertambah. Pindai ulang untuk melihat `android-storage-free` setelahnya.

<a id="android-enable-package-verifier"></a>
**`android.enable-package-verifier`.** Menulis `package_verifier_enable=1` di pengaturan global ponsel (verifikasi paket/Play Protect versi AOSP). `reversible`: butuh persetujuan walau dipicu. Verify membaca balik nilainya: `settings get` harus mencetak tepat satu baris `1` (langkah katalog `expect_line`, hanya mesin Python); pindai ulang untuk melihat `android-play-protect`. Rollback otomatis (bila execute atau verify gagal) menghapus kunci itu (`settings delete`) sehingga ponsel kembali ke nilai bawaan Android (aktif). Nilai sebelumnya **tidak** ditangkap: bila sebelumnya `0` eksplisit, rollback tidak mengembalikan `0`. Aksi ini tidak mengubah persetujuan pengguna (`package_verifier_user_consent`) di aplikasi Play Protect; bagian itu dilakukan operator di ponsel.

<a id="android-reboot"></a>
**`android.reboot`.** Memulai ulang ponsel secara normal (bukan ke bootloader atau recovery). Risiko `safe` karena tidak ada perubahan persisten selain kehilangan keadaan yang belum tersimpan di ponsel; tanpa pemicu sehingga tidak pernah jalan otomatis. Setelah `reboot` ID transport berubah, jadi tahap verify mencari ponsel lagi (maksimum 150 detik, tiap 3 detik) dan hanya lulus bila ponsel muncul kembali sebagai perangkat ADB yang disetujui dengan `opaque_id` yang sama; layar ponsel yang terkunci atau prompt RSA baru membuat verify `fail` (`device-not-authorized`) padahal reboot-nya berhasil.

### Parameter `android_device`

Aksi Android menyebut ponselnya lewat parameter bertipe `android_device`, yang **tidak pernah** berasal dari operator, evidence, atau model (`--param` untuk tipe ini diabaikan). Mesin menyelesaikannya saat eksekusi, setelah persetujuan:

1. `target_ref` (`and-N`) usulan harus ada di `target_systems[]` evidence dengan `family: android` dan `opaque_id`.
2. Mesin membaca ulang inventaris USB (sysfs) dan `adb devices -l`, menyusun target seperti `scan-android.py`, lalu mengambil `and-N` yang sama.
3. Ia menolak bila: tidak ada (`device-absent`); lebih dari satu target punya identitas yang sama (`device-ambiguous`); `opaque_id` sekarang tidak sama dengan evidence, misalnya ponsel lain di port itu atau penomoran bergeser (`device-mismatch`); atau status ADB bukan `device` (`device-not-authorized`: `unauthorized`, `offline`, `recovery`, `sideload`, `bootloader`, atau tanpa ADB).
4. Bila lolos, `{android_device}` dirender sebagai bilangan bulat ID transport untuk `adb -t`. ID itu hanya ada di argv proses anak: **tidak** masuk journal, laporan, atau layar (kartu persetujuan menampilkan `<android and-0>`).

Penolakan dicatat di journal sebagai `precondition fail` dengan `reason` bertipe (`device-absent`, `device-not-authorized`, `device-ambiguous`, `device-mismatch`) dan hasil akhir `skipped`; tidak ada perintah yang dikirim ke ponsel. Tahap verify dan rollback mencari ulang ponsel (ID transport bisa berubah). Mesin memberi proses anak `HOME` dan `USER` (kunci RSA ADB ada di `~/.android`) dan mematikan mDNS; kunci API tidak pernah diteruskan. Di sesi live mesin menghentikan server ADB yang ia mulai (`adb kill-server`); di mode host server milik operator dibiarkan.

### Batas yang dijaga validator katalog

`scripts/lib/repair_catalog.py` menolak aksi Android yang: tidak memakai tepat satu `android_device`; memanggil `adb` selain dengan `-t {android_device}`; memakai sub-perintah di luar `shell`, `reboot` (tanpa argumen), `get-state`; memakai program `shell` di luar `pm trim-caches`, `settings get|put|delete global <kunci>`, `df`; menaruh placeholder setelah `shell`; atau berjalan di platform selain `live-linux` dan `linux-host`. Jadi `root`, `install`, `push`, `pull`, `sideload`, `remount`, `reboot bootloader|recovery`, `rm`, `sh`, wipe, dan factory reset tidak dapat masuk katalog tanpa mengubah validator itu sendiri. Mesin host Windows dan macOS menerima katalog yang sama dan menandai `android_device` sebagai tidak didukung (aksi Android tidak pernah berlaku di platform mereka).

### Cara memakai

**Live USB (launcher).** Setelah pemindaian OS selesai, `scripts/launch-hermes-rescue.sh` memeriksa USB (`scan-android.py --count-android`). Bila ada ponsel dan sesi interaktif, launcher menampilkan tabel semua perangkat USB lalu bertanya (default **tidak**; tanpa terminal dilewati) apakah ponsel dipindai. Bila ya: pemindaian read-only sebagai pengguna desktop (kunci ADB ada di `~/.android`) ke `<state-dir>/reports/android-evidence-<stamp>.json`, lalu `rescue-repair.py --scope android` dengan kebijakan yang sama (`--repair-policy`, default `approve-each`), pemindaian ulang bila ada aksi yang dijalankan (`android-evidence-<stamp>-after.json`), dan **laporan run tersendiri** (`run_id` berakhiran `-android`; `rescue-report.py` menerima satu evidence per laporan). Analisis cloud tidak diminta untuk evidence ponsel; Hermes membacanya bila operator meminta. Lewati seluruh fase ini dengan `--no-target-scan` atau `--scope` tanpa `all`/`android`.

**Linux host (`host/rescue-linux.sh` belum memasangnya).** Pakai skrip langsung dari bundel, sebagai pengguna biasa:

```bash
python3 scripts/scan-android.py --list-usb
python3 scripts/scan-android.py --source-platform linux-host --repair-policy approve-each --output /tmp/android-evidence.json
python3 scripts/rescue-repair.py --evidence /tmp/android-evidence.json --scope android --journal /tmp/android-journal.jsonl --list
python3 scripts/rescue-repair.py --evidence /tmp/android-evidence.json --scope android --journal /tmp/android-journal.jsonl
python3 scripts/rescue-repair.py --evidence /tmp/android-evidence.json --journal /tmp/android-journal.jsonl --select android.reboot:and-0
```

Perintah terakhir menjalankan aksi operator (`android.reboot` tidak punya pemicu) dan meminta `ya`/`yes`; tanpa terminal tambahkan `--approve android.reboot`. Di mode host server `adb` milik operator dipakai apa adanya.

### Untuk operator

- Aksi Android **tidak pernah** berjalan tanpa persetujuan Anda kecuali `android.trim-caches` pada kebijakan `auto-safe`. Untuk memperbaiki lebih jauh (hapus aplikasi, factory reset, root) lakukan sendiri di ponsel atau lewat layanan resmi pabrikan; toolkit ini tidak melakukannya. Flashing hanya lewat perintah yang Anda ketik sendiri ([di bawah](#flashing-dan-unbrick-52)).
- Bila penolakan `device-mismatch` muncul, jangan pindahkan atau ganti ponsel di antara pemindaian dan perbaikan; pindai ulang agar `and-N` dan `opaque_id` cocok lagi.
- Bila `device-not-authorized`: buka kunci ponsel dan setujui "Izinkan USB debugging", lalu jalankan ulang.

## Flashing dan unbrick (#52)

Fitur ini **dipanggil operator** dengan `rescue-repair.py --select ... --param ...`; launcher live tidak menawarkannya dan tidak ada yang berjalan otomatis. Semua aksi ada di `rescue-ai/v1/catalog/android.json`, hanya dijalankan mesin Python (platform `live-linux` dan `linux-host`; mesin Windows/macOS menerima katalognya tetapi tidak pernah mengusulkannya), dan **tidak pernah** diusulkan oleh pemicu pemeriksaan: hanya `--select` operator (atau usulan AI yang tetap harus Anda setujui). Paket `fastboot` dan `heimdall-flash` dipasang oleh [persistence](persistence.md) (aturan udev dari `android-sdk-platform-tools-common`).

| Jalur | Keputusan |
|---|---|
| Fastboot | **Diimplementasikan**: ganti slot A/B, flash image zip resmi (`fastboot update`, tanpa `-w`), flash partisi dalam allowlist, reboot |
| Membuka kunci bootloader | **Tidak diotomatisasi**. Toolkit mendeteksi status kunci, **menolak** flashing pada bootloader terkunci, dan memandu operator ([di bawah](#bootloader-terkunci)) |
| Samsung Download/Odin | **EKSPERIMENTAL** lewat Heimdall: baca PIT (read-only), flash partisi allowlist dari firmware resmi yang di-hash operator |
| Qualcomm EDL (9008), MediaTek BROM | **Deteksi dan panduan saja** ([di bawah](#edl-dan-brom)) |

### Aksi fastboot dan Heimdall

| Aksi | Risiko | Argv (ringkas) | Verify | Rollback |
|---|---|---|---|---|
| `android.fastboot-set-active-slot` | `reversible` | `fastboot -s usb:PORT --set-active=SLOT` | `getvar current-slot` harus berisi baris `current-slot: SLOT` | otomatis: `--set-active=` slot sebelumnya (dibaca mesin dari ponsel tepat sebelum aksi) |
| `android.fastboot-reboot` | `safe` | `fastboot -s usb:PORT reboot` | `fastboot devices` (hanya membuktikan fastboot masih menjawab; pindai ulang untuk melihat ponsel keluar dari fastboot) | tidak ada |
| `android.fastboot-flash-partition` | `destructive` | `fastboot -s usb:PORT flash PARTISI FILE` | `getvar product` (kode keluar 0) | manual dari backup ([di bawah](#rollback-flash)) |
| `android.fastboot-update-image` | `destructive` | `fastboot -s usb:PORT update FILE` (tanpa `-w`: data pengguna dipertahankan) | `getvar product` (kode keluar 0) | manual dari backup |
| `android.heimdall-flash-partition` (**EKSPERIMENTAL**) | `destructive` | `heimdall flash --PARTISI FILE --no-reboot` | `heimdall detect` | manual dari backup |

`PARTISI` fastboot: `boot`, `init_boot`, `vendor_boot`, `dtbo`, `vbmeta`, `vbmeta_system`, `recovery`. Heimdall: `BOOT`, `RECOVERY`, `VBMETA`, `DTBO`. Tidak pernah dari aksi partisi: `bootloader`, `radio`, `modem`, `persist`, `efs`, `frp`, `devinfo`, `modemst*`, `fsg`, `userdata`. Tidak ada aksi untuk `erase`, `format`, `-w`, `flashing unlock/lock`, `oem ...`, `flash-all`, atau `reboot bootloader`.

<a id="android-fastboot-set-active-slot"></a>
**`android.fastboot-set-active-slot`.** Untuk bootloop setelah pembaruan pada ponsel A/B: pindah ke slot lain yang masih utuh. Parameter `slot` (`a` atau `b`) wajib dari operator; slot sebelumnya dibaca mesin (`getvar current-slot`) dan dipakai untuk rollback otomatis bila verify gagal. Ponsel non-A/B (slot tidak terbaca) ditolak (`identity-mismatch`). Slot tujuan harus yang berisi sistem yang bisa boot; fastboot tidak dapat memeriksanya.

<a id="android-fastboot-reboot"></a>
**`android.fastboot-reboot`.** Keluar dari fastboot ke Android normal. `safe`, tanpa pemicu.

<a id="android-fastboot-flash-partition"></a>
**`android.fastboot-flash-partition`.** Menulis satu image ke satu partisi allowlist. Parameter: `partition`, `firmware` (path absolut file `.img`), `firmware_sha256`. Perlu `--backup-ref` dan `action_id` diketik. Verify hanya membuktikan bootloader masih menjawab setelah penulisan; **fastboot tidak dapat membaca balik isi partisi**, jadi keberhasilan flash sebenarnya baru terbukti saat ponsel boot.

<a id="android-fastboot-update-image"></a>
**`android.fastboot-update-image`.** Memasang image resmi lengkap dari **zip image dalam** (`image-<produk>-<build>.zip` di dalam zip factory image; file `android-info.txt` harus ada di akarnya). Zip factory *luar* (berisi `flash-all.sh`, `bootloader-*.img`, `radio-*.img`) ditolak: ekstrak zip dalamnya sendiri. Isi zip tidak pernah diekstrak atau dijalankan: skrip seperti `flash-all.sh` tidak dieksekusi, `android-info.txt` hanya dibaca sebagai data. Zip yang memuat image `bootloader`, `radio`, `modem`, `persist`, `efs`, `frp`, `devinfo`, `fsg`, atau `userdata` ditolak. Memperbarui bootloader/radio dari zip luar dilakukan operator sendiri lewat alat resmi pabrikan.

<a id="android-heimdall-flash-partition"></a>
**`android.heimdall-flash-partition` (EKSPERIMENTAL).** Ponsel Samsung dalam mode Download. Prasyarat: `heimdall detect` berhasil, dan `heimdall print-pit --no-reboot` (read-only) memuat baris `Partition Name: <PARTISI>`; mesin menolak kecuali **tepat satu** perangkat Samsung mode Download ada di USB dan itu adalah `and-N` usulan dengan `opaque_id` yang sama (Heimdall menyapa satu-satunya perangkat yang ia temukan; perangkat kedua yang tidak sengaja akan ikut tertimpa). Heimdall tidak memeriksa kecocokan firmware dengan perangkat selain nama partisi di PIT: **operatorlah yang memastikan firmware resmi untuk model persis itu**. Heimdall pada ponsel Samsung baru (Android 10 ke atas, partisi dinamis, vbmeta, Knox) sering gagal atau tidak didukung; tidak dapat diverifikasi tanpa perangkat nyata.

### Parameter baru

| Tipe | Asal | Perilaku |
|---|---|---|
| `fastboot_device` | mesin | Seperti `android_device`, dicari ulang saat eksekusi (inventaris USB + `fastboot devices -l`; `opaque_id` harus sama dengan evidence; ponsel harus dalam mode fastboot dan boleh diakses pengguna ini). Dirender sebagai `usb:<port>`, yang diterima `fastboot -s` (kode sumber AOSP `fastboot.cpp` membandingkan argumen dengan nomor seri **atau** `usb:<nama sysfs>`), jadi serial tidak pernah masuk argv. Selektor harus benar-benar menjawab `getvar product` sebelum dipakai; bila tidak, aksi ditolak (`device-absent`) |
| `fastboot_slot` | mesin | Slot aktif (`a`/`b`) yang dibaca tepat sebelum aksi, hanya untuk rollback `--set-active=` |
| `firmware_file` | operator | `--param AKSI.firmware=/path/absolut`. Path absolut, ternormalisasi, tanpa karakter kontrol. Dibuka sekali dengan `O_NOFOLLOW` (symlink di komponen akhir ditolak), harus berkas biasa dengan ukuran 4 KiB sampai 2 GiB (image) atau 1 MiB sampai 16 GiB (zip), di-hash lewat deskriptor itu, lalu diberikan ke proses anak sebagai `/dev/fd/N`: byte yang di-hash adalah byte yang di-flash. Path tidak pernah masuk journal, laporan, atau layar |
| `sha256` | operator | `--param AKSI.firmware_sha256=<64 hex>` dari situs resmi pabrikan. Wajib sama dengan hash berkas, bila tidak aksi ditolak (`firmware-hash-mismatch`). Hanya SHA-256 ini yang masuk journal |

Alasan penolakan baru di journal (`precondition fail`, hasil akhir `skipped`, tidak ada yang dikirim ke ponsel): `bootloader-locked`, `identity-mismatch` (produk tidak cocok dengan `android-info.txt`, `android-info.txt` tanpa baris `require board/product`, atau slot tidak terbaca), `firmware-invalid` (path/berkas/zip tidak memenuhi syarat), `firmware-hash-mismatch`; ditambah `device-absent`, `device-not-authorized`, `device-ambiguous`, `device-mismatch` ([parameter android_device](#parameter-android_device)).

### Guard (pemeriksaan native sebelum perintah apa pun)

| Guard | Aksi | Syarat |
|---|---|---|
| `bootloader-unlocked` | flash partisi, update image | `fastboot getvar unlocked` berisi `yes`; selain itu (termasuk tidak terbaca) `bootloader-locked` dan panduan buka kunci manual |
| `image-matches-device` | update image | Setiap baris `require board=a|b` dan `require product=...` di `android-info.txt` harus memuat nilai `getvar product` ponsel; tanpa baris seperti itu identitas tidak dapat dibuktikan dan zip ditolak (`identity-mismatch`) |
| `single-download-mode-device` | Heimdall | Tepat satu perangkat Samsung mode Download di USB, yaitu `and-N` usulan |

Nilai `product` hanya ada di memori mesin; tidak ditampilkan, tidak masuk journal atau evidence.

### Pendeteksian (read-only)

`scan-android.py` untuk ponsel dalam mode tingkat rendah menambah check berikut (hanya untuk mode itu; `fastboot devices -l` dipetakan ke port lewat bidang `usb:`, lalu `fastboot -s usb:PORT getvar` untuk `unlocked`, `current-slot`, `slot-count`, `is-userspace`; `product` **tidak** dibaca di pemindaian):

| Check | Nilai | Status |
|---|---|---|
| `android-fastboot-lock-state` | - | terkunci `pass`, tidak terkunci `warn` (flashing mungkin), tidak terbaca `unknown` |
| `android-fastboot-slot` | `count` = jumlah slot | `pass` bila A/B dan slot aktif `a`/`b`; `not_applicable` bila 1 slot; `unknown` bila tidak terbaca |
| `android-fastboot-userspace` | - | bootloader `pass`; fastbootd (userspace) `warn` |
| `android-heimdall-detect` | - | mode Download Samsung: `pass` bila `heimdall detect` melihatnya, `warn` bila tidak, `unknown` tanpa `heimdall` atau bila bukan tepat satu perangkat Download |
| `android-low-level-mode` | - | EDL, MediaTek BROM/preloader, Unisoc download: selalu `warn` (panduan) |

<a id="bootloader-terkunci"></a>
### Bootloader terkunci

Toolkit **tidak membuka kunci bootloader** dan menolak flashing pada bootloader terkunci. Membuka kunci (`fastboot flashing unlock` atau prosedur pabrikan) **menghapus semua data pengguna**, dan sebagian pabrikan mensyaratkan akun/izin khusus atau tidak mengizinkannya sama sekali. Bila Anda memutuskan membukanya: cadangkan dulu bila ponsel masih bisa dibaca, ikuti prosedur resmi pabrikan untuk model persis itu, lalu jalankan ulang aksi. Jangan memakai alat atau firmware tidak resmi.

<a id="edl-dan-brom"></a>
### EDL dan BROM

Ponsel di mode Qualcomm EDL (9008) atau MediaTek BROM/preloader biasanya mati total atau sengaja dimasukkan ke mode itu. Toolkit hanya mendeteksi dan memberi panduan: **berhenti dan bawa ke pusat servis resmi**. Tidak ada alat pip, programmer firehose pihak ketiga, atau exploit BROM (mtkclient) di USB ini dan tidak akan ditambahkan. Preloader MediaTek juga muncul beberapa detik pada setiap start normal.

<a id="rollback-flash"></a>
### Backup dan rollback

Aksi `destructive` butuh `--backup-ref FILE` (berkas biasa tidak kosong; journal mencatat ukuran dan sidik jarinya, bukan path) dan `action_id` diketik. Fastboot tidak dapat membaca balik partisi, jadi backup harus dibuat **sebelum** bootloader dibuka dan sebelum flash: untuk partisi `boot`/`vendor_boot`/`init_boot` salin image yang sedang terpasang dari paket firmware resmi yang sama dengan sistem sekarang atau dari ekstraksi di ponsel yang masih bisa boot; berkas itu (atau catatan SHA-256 firmware yang sedang terpasang) adalah referensi `--backup-ref`, dan itulah yang Anda flash balik secara **manual** bila ponsel tidak boot sesudahnya. Rollback otomatis hanya ada untuk pergantian slot.

### Contoh perintah

Salin firmware resmi dan hash resmi ke USB atau disk, lalu (sebagai pengguna biasa, ponsel dalam fastboot, setelah `scan-android.py --output ...`). Replace paths with your own; `and-0` is the phone number shown by the scan.

```bash
python3 scripts/scan-android.py --list-usb
python3 scripts/scan-android.py --output ~/android-evidence.json
python3 scripts/rescue-repair.py --evidence ~/android-evidence.json --journal ~/android-journal.jsonl --list

# bootloop, A/B: ganti slot (reversible) / switch slot
python3 scripts/rescue-repair.py --evidence ~/android-evidence.json --journal ~/android-journal.jsonl \
  --select android.fastboot-set-active-slot:and-0 --param android.fastboot-set-active-slot.slot=b

# soft-brick: image resmi persis produk itu (zip dalam), data dipertahankan / official image of the exact product, data kept
python3 scripts/rescue-repair.py --evidence ~/android-evidence.json --journal ~/android-journal.jsonl \
  --backup-ref ~/backup-boot.img --select android.fastboot-update-image:and-0 \
  --param android.fastboot-update-image.firmware=/media/usb/image-produk-build.zip \
  --param android.fastboot-update-image.firmware_sha256=<sha256 resmi / official sha256>

# satu partisi / one partition
python3 scripts/rescue-repair.py --evidence ~/android-evidence.json --journal ~/android-journal.jsonl \
  --backup-ref ~/backup-boot.img --select android.fastboot-flash-partition:and-0 \
  --param android.fastboot-flash-partition.partition=boot \
  --param android.fastboot-flash-partition.firmware=/media/usb/boot.img \
  --param android.fastboot-flash-partition.firmware_sha256=<sha256 resmi / official sha256>
```

Mesin meminta `ya`/`yes`, atau untuk aksi `destructive` mengetik `action_id`; tanpa terminal gunakan `--approve ACTION_ID`. Contoh Heimdall (EKSPERIMENTAL, tepat satu perangkat Samsung mode Download, firmware hasil ekstraksi `.tar.md5` resmi): `--select android.heimdall-flash-partition:and-0 --param android.heimdall-flash-partition.partition=RECOVERY --param ...firmware=/media/usb/recovery.img --param ...firmware_sha256=...`.

### Risiko

| Risiko | Akibat | Pengendali |
|---|---|---|
| Firmware tidak resmi atau rusak | Ponsel tidak boot, malware di partisi boot | SHA-256 dari operator wajib cocok; hanya sumber resmi |
| Firmware untuk model lain | Brick | `image-matches-device` (zip), nama partisi di PIT (Heimdall); operator memastikan model |
| Bootloader terkunci | Flash gagal atau ditolak | Ditolak toolkit; tidak ada buka kunci otomatis |
| Salah port/ponsel | Ponsel lain tertimpa | `fastboot_device` dicari ulang dan `opaque_id` dicocokkan; Heimdall hanya bila tepat satu perangkat Download |
| Partisi kritis tertimpa | Brick permanen (IMEI, kalibrasi, FRP) | Allowlist partisi; zip dengan `bootloader`/`radio`/`modem`/`persist`/`efs`/`frp`/`userdata` ditolak |
| Kabel/daya putus saat flash | Partisi setengah tertulis | Gunakan kabel data asli, baterai cukup, port langsung; pemulihan manual dari backup |
| Heimdall pada Samsung baru | Gagal atau perilaku tidak terduga | EKSPERIMENTAL; verifikasi hanya dengan perangkat nyata |
