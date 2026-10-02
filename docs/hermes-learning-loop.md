# Hermes Rescue Learning Loop

> Managed by **ahlikoding.com** and **satpamsiber.com** from **ahliweb.com**.

```mermaid
flowchart LR
    A[ahliweb.com] --> K[ahlikoding.com]
    A --> S[satpamsiber.com]
    K --> H[Hermes implementation]
    S --> P[Security policy]
    H --> U[Approved USB release]
    P --> U
```

## Tujuan

```mermaid
flowchart LR
    USB[USB rescue] --> H[Hermes]
    H --> L[Learning loop]
    L --> S[Safer future diagnosis]
```

Membuat USB rescue semakin efektif dari kasus ke kasus melalui Hermes Agent, tanpa mengubah USB menjadi agen yang melakukan self-modification tanpa kontrol. OpenCode Go tetap menjadi provider analisis; Hermes menjadi orchestrator, memory/skill manager, approval gate, dan verifier.

## Status implementasi

Dokumen ini menggabungkan apa yang **sudah ada** dan rancangan yang **belum ada**. Label: **Implemented** (level source, `make check`), **Environment-blocked** (butuh jaringan, kunci, atau token), **Planned** (rancangan saja). Bagian di bawah yang tidak tercantum sebagai Implemented adalah Planned.

| Bagian | Status |
|---|---|
| Profile Hermes terpisah (`profiles/rescue-hermes/`: `SOUL.md`, `AGENTS.md`, skill `rescue-boot-diagnosis`, `rescue-target-os`, `rescue-skill-submission`, `rescue-android`, `rescue-printer`, `rescue-autorun`) dipasang ke `HERMES_HOME` yang terisolasi oleh `install-hermes-rescue.sh` | Implemented |
| OpenCode Go sebagai satu-satunya provider (`custom`, `mimo-v2.6-flash`); memory Hermes dengan `write_approval: true` dan tanpa profil pengguna | Implemented |
| Gerbang kesiapan hardware sebelum diagnosis dan laporan JSON | Implemented |
| Evidence terbatas (schema 1.2) dan analyzer yang hanya menghasilkan teks | Implemented |
| Perbaikan hanya lewat katalog aksi bertipe dan mesin `rescue-repair.py` (kebijakan, persetujuan, backup, verify, rollback, journal berantai hash); AI hanya mengusulkan `action_id` ([repair-framework.md](repair-framework.md)) | Implemented |
| Karantina malware yang dapat dibalik dan aturan penghapusan ([malware.md](malware.md)) | Implemented |
| Laporan proses per run yang dibaca Hermes lebih dulu ([run-report.md](run-report.md)) | Implemented |
| Pengajuan kandidat skill ke GitHub Issues setelah sanitasi dan konfirmasi operator ([skill-submission.md](skill-submission.md)) | Implemented; panggilan GitHub nyata Environment-blocked |
| Autorun Hermes: giliran pertama tetap (`profiles/rescue-hermes/kickoff.md`), skill `rescue-autorun`, follow-up bertipe read-only `scripts/rescue-followup.py` (skema `rescue-ai/v1/followup.schema.json`), `approvals.deny` di `config/hermes-rescue.config.yaml` ([bagian Autorun](#autorun-hermes-69)) | Implemented (level source; sesi Hermes nyata dan cloud Environment-blocked) |
| Launcher live/host yang mengirim `kickoff.md` sebagai giliran pertama dan memanggil `rescue-followup` otomatis; follow-up native Windows | Planned (dikerjakan di sisi launcher, terpisah dari isu ini) |
| Direktori `cases/`, `learning/candidates/`, `learning/approved/` di state (dibuat installer, kosong) | Implemented (hanya direktori) |
| `case.json`, `operator-feedback.json`, `verification.json`, `learning-candidate.json`, `case_signature` dan retrieval, label feedback, kandidat memory otomatis, evaluasi regresi, metrik, promosi bertanda tangan | Planned |
| Toolset `rescue_read_only`, adapter tool bertipe dengan `tool_id`, penonaktifan channel messaging/webhook lewat config, ledger terenkripsi, `releases/manifest.json` | Planned (template config saat ini tidak menetapkannya) |

```mermaid
flowchart LR
    EV[Evidence 1.2] --> AN[Analyzer: teks]
    AN --> CT[action_id dari katalog]
    CT --> EN[rescue-repair.py + persetujuan operator]
    EN --> JR[(Journal)]
    JR --> RP[Laporan proses]
    RP --> H[Hermes membaca report.md]
    H --> SS[Kandidat skill: submit-skill.py]
    SS --> GH[GitHub issue skill-candidate]
    GH -. Planned .-> PR[Tes, review, promosi bertanda tangan]
```

## Batas istilah

```mermaid
flowchart TD
    R[Rescue OMES companion] --> E[Evidence + policy + lifecycle]
    E --> H[Hermes runtime]
    H --> G[OpenCode Go]
    R -. does not modify .-> O[ahliweb/omes core]
```

Repository ini adalah companion mandiri. Dokumen ini memakai istilah **Rescue OMES** untuk lapisan operasi lokal yang mengatur evidence, policy, lifecycle, dan verifikasi Hermes di media rescue. Ini bukan perubahan pada repository `ahliweb/omes`.

## Arsitektur target

Bagian ini adalah rancangan target; lihat [Status implementasi](#status-implementasi) untuk yang sudah ada.

```mermaid
flowchart LR
    L[Linux Mint XFCE / Pi] --> R[Rescue OMES controller]
    R --> H[Hermes Rescue Profile]
    H --> G[OpenCode Go]
    G --> O[Operator decision]
    O --> V[Verified outcome]
    V --> C[Candidate learning]
```

```text
Linux Mint XFCE Live / Raspberry Pi
        |
        v
Rescue OMES controller
  - allowlisted collectors
  - evidence sanitizer
  - case ledger
  - policy and approval gate
  - verifier and rollback record
        |
        v
Hermes Rescue Profile
  - SOUL.md / context
  - rescue skills (read-only bundle)
  - local memory snapshot
  - session search
  - tool adapters
        |
        v
OpenCode Go
  - diagnosis hypotheses
  - next read-only checks
  - structured repair plan
        |
        v
Operator decision + verified outcome
        |
        +--> candidate memory/skill --> evaluation --> promotion
```

Hermes tidak boleh menerima tool generik `shell_exec`. Setiap tool harus berupa adapter typed, allowlisted, timeout-bounded, read-only by default, dan menghasilkan output yang dapat diverifikasi. Yang berlaku hari ini: collector dan modul deteksi read-only dengan allowlist tetap, serta aksi katalog bertipe yang dijalankan mesin perbaikan (bukan oleh model); profil Hermes melarang mengeksekusi perintah dari log atau output model.

## Gate kesiapan sebelum diagnosis

```mermaid
flowchart LR
    B[Boot Linux Mint XFCE] --> H[Hermes tersedia]
    H --> P[Hardware preflight]
    P --> A{Minimum terpenuhi?}
    A -- tidak --> R[Laporan gagal + berhenti]
    A -- ya --> D[Mulai diagnosis]
```

Sebelum loop kasus dimulai (**Implemented**), launcher menjalankan pemeriksaan CPU, RAM, VGA/display,
route/DNS/HTTPS, dan USB live media. Mode `auto` adalah default dan menjalankan
semua langkah tanpa interaksi; mode `wizard` meminta konfirmasi operator pada
setiap langkah. Laporan disimpan sebagai JSON di `<state-dir>/reports/` dan
menjadi bukti awal yang terpisah dari `case.json`. Kegagalan atau status unknown
pada syarat wajib mencegah Hermes mulai, sedangkan keberhasilan software tidak
menggantikan uji boot firmware pada PC fisik.

## Bagaimana sistem menjadi lebih cerdas

```mermaid
flowchart LR
    C[Case] --> R[Retrieve]
    R --> D[Diagnose]
    D --> F[Feedback]
    F --> E[Evaluate]
    E --> P[Promote approved skill]
```

Bagian 1 sampai 4 di bawah (artefak kasus, retrieval, label feedback, promosi bertahap) adalah rancangan **Planned**, kecuali pengajuan kandidat skill yang sudah **Implemented** ([skill-submission.md](skill-submission.md)).

### 1. Belajar dari kasus, bukan dari raw transcript

```mermaid
flowchart TD
    S[Session] --> C[case.json]
    S --> F[operator-feedback.json]
    S --> V[verification.json]
    C --> L[learning-candidate.json]
    F --> L
    V --> L
    L --> Q[Promotion gate]
```
Setiap sesi menghasilkan empat artefak terpisah:

- `case.json`: signature masalah, platform, boot mode, evidence IDs, hipotesis, dan hasil akhir;
- `operator-feedback.json`: diagnosis benar/salah, tindakan yang membantu, tindakan yang tidak relevan, dan catatan singkat;
- `verification.json`: bukti bahwa hasil benar-benar terjadi, misalnya boot kembali berhasil atau disk tetap tidak berubah;
- `learning-candidate.json`: aturan/playbook kandidat yang dihasilkan dari kasus.

Prompt, respons model lengkap, serial number, credential, raw journal, dan path pribadi tidak masuk ke memory jangka panjang. Raw evidence tetap berada di vault lokal terpisah dengan hash dan retention policy.

### 2. Retrieval sebelum diagnosis

```mermaid
flowchart LR
    E[Evidence] --> S[Deterministic case signature]
    S --> M[Approved memory/skills]
    M --> H[Hermes context]
    H --> G[OpenCode Go hypotheses]
```

Sebelum Hermes meminta OpenCode Go menganalisis kasus baru, controller membuat `case_signature` deterministik:

- `boot_mode`: UEFI/BIOS;
- `symptom_class`: no-boot, boot-loop, filesystem-error, disk-I/O, network, unknown;
- `storage_class`: SATA/NVMe/USB/unknown;
- `filesystem_family`: ext4/NTFS/LVM/RAID/unknown;
- `firmware_signals`: Secure Boot, boot entry present/missing;
- hasil check allowlist dan statusnya.

Hermes mengambil skill/playbook yang cocok berdasarkan signature dan confidence. Model tidak diberi kebebasan memilih command; model hanya memilih dari daftar check dan tool yang tersedia.

### 3. Feedback operator sebagai label

```mermaid
flowchart TD
    H[Hermes hypothesis] --> O[Operator label]
    O --> C[confirmed]
    O --> P[partially_correct]
    O --> W[wrong]
    O --> U[unsafe]
    O --> N[unresolved]
    C --> E[Evaluation dataset]
    U --> B[Promotion blocked]
```

Operator memilih salah satu:

- `confirmed`: diagnosis dan langkah berikutnya tepat;
- `partially_correct`: hipotesis berguna tetapi belum lengkap;
- `wrong`: hipotesis salah;
- `unsafe`: usulan berisiko atau melanggar policy;
- `unresolved`: evidence belum cukup.

Feedback harus dikaitkan dengan evidence hash dan case ID. Tanpa feedback dan verification, kasus tidak boleh dipromosikan menjadi skill.

### 4. Promosi bertahap

Pengajuan kandidat skill ke issue GitHub (setelah sanitasi dan konfirmasi operator) dijelaskan di [skill-submission.md](skill-submission.md).

```mermaid
flowchart LR
    S[Session-only] --> M[Candidate memory]
    M --> K[Candidate skill]
    K --> T[Regression tests]
    T --> A[Operator approval]
    A --> R[Signed release bundle]
```

```text
session-only
  -> candidate memory
  -> candidate skill/playbook
  -> offline regression test
  -> operator approval
  -> approved rescue skill bundle
  -> signed USB release
```

Aturan promosi minimum:

- satu kasus tidak pernah langsung mengubah skill produksi;
- kandidat harus lolos schema dan secret scan;
- kandidat tidak boleh menambah executable command baru tanpa review;
- kandidat harus diuji terhadap kasus sebelumnya;
- minimal tiga kasus independen dengan outcome terverifikasi sebelum menjadi playbook default;
- kasus dengan label `unsafe` otomatis memblokir promosi.

## Struktur direktori yang disarankan (Planned)

Yang sudah ada di state hanyalah `cases/`, `learning/candidates/`, dan `learning/approved/`; sisanya adalah rancangan.

```mermaid
flowchart TD
    P[profiles/rescue-hermes] --> R[Read-only runtime policy]
    C[cases] --> L[Learning candidates]
    L --> A[Approved skills]
    T[tools] --> E[Evidence]
    E --> C
    M[releases] --> P
    M --> A
```

```text
rescue-omes/
  policy/
    allowed-checks.yaml
    approval-policy.yaml
    retention.yaml
  profiles/
    rescue-hermes/
      SOUL.md
      AGENTS.md
      skills/
        boot-diagnosis/SKILL.md
        disk-health/SKILL.md
        filesystem-recovery/SKILL.md
        network-rescue/SKILL.md
      config.yaml.template
  cases/
    sanitized/
    feedback/
    verification/
  learning/
    candidates/
    approved/
    eval/
  tools/
    collect-boot-evidence
    collect-disk-evidence
    collect-network-evidence
    verify-outcome
  releases/
    manifest.json
    checksums.txt
```

`profiles/rescue-hermes` dan `learning/approved` dipasang read-only ketika boot normal. Hanya `cases/`, `learning/candidates/`, dan session workspace yang writable.

## Autorun Hermes (#69)

Hasil lapangan 2026-10-01 (v0.6.0): analisis menyarankan pemeriksaan read-only lanjutan (atribut SMART terperinci, penyebab `windows-system-files` warn, penyebab `malware-scan` warn tanpa temuan) tetapi tidak ada yang menjalankannya; hasil self-test SMART tidak pernah dibaca; Hermes menyangka root adalah overlay RAM (`/cow`) padahal persistence Ventoy aktif. Autorun menutup celah itu **tanpa** memberi Hermes jalan untuk menjalankan perintah bebas.

```mermaid
flowchart TD
    L[Launcher: scan, analisis, perbaikan, laporan] --> F["rescue-followup.py: follow-up bertipe read-only"]
    F --> FF[("followup-run_id.json: angka, boolean, enum tertutup")]
    L --> K["Giliran pertama tetap: kickoff.md, path relatif"]
    K --> H[Hermes dengan cwd = folder laporan]
    FF --> H
    H --> SK[Skill rescue-autorun]
    SK --> C1["Perintah 1: rescue-followup bila belum ada"]
    SK --> C2["Perintah 2: rescue-repair.py --policy auto-safe --select aksi safe yang diusulkan"]
    SK --> M["Semua perintah lain: persetujuan manual Hermes"]
    M --> D{"approvals.deny cocok?"}
    D -- ya --> X[Diblokir, juga di bawah yolo]
    D -- tidak --> O[Operator menyetujui]
```

| Bagian | Isi | Status |
|---|---|---|
| Giliran pertama | `profiles/rescue-hermes/kickoff.md`: Bahasa Indonesia singkat dengan satu baris Inggris. Hermes mulai dengan cwd = folder laporan, jadi hanya path relatif (`index.md`, `run-*/report.md`, `followup-*.json`, `analysis-*.md`); tidak ada path absolut atau nama pengguna. Tes memeriksa hal ini | Implemented (berkas dan tes); pengiriman oleh launcher Planned |
| Skill `rescue-autorun` | (1) ringkas laporan per domain (unknown bukan sehat), (2) jalankan follow-up bila belum ada untuk run terbaru, (3) jalankan aksi katalog `safe` yang diusulkan tetapi belum jalan, (4) beri tahu kapan menjalankan ulang follow-up bila self-test masih berjalan, (5) ringkasan bernomor dengan kondisi berhenti | Implemented |
| Dua perintah tanpa tanya | `rescue-followup` (argumen tetap) dan `rescue-repair.py --policy auto-safe --select <action_id yang diusulkan dan safe>` (hanya mode Linux). Tidak pernah `--approve`, `--param`, `--backup-ref`; yang bukan `safe` dijelaskan dan disetujui operator di mesin. Catatan: `auto-safe` menjalankan otomatis hanya aksi pemicu katalog (`catalog-trigger`) berisiko `safe`; usulan `--select` berasal `operator` dan tetap meminta persetujuan di mesin | Implemented |
| `approvals` di config Hermes | `mode: manual` dan `deny` (glob `fnmatch` pada varian perintah huruf kecil; memblokir juga di bawah `--yolo`): `*--approve*`, `*--backup-ref*`, `*--param*`, `dd *`, `*mkfs*`, `*wipefs*`, `*parted*`, `*fdisk*`, `*sgdisk*`, `*grub-install*`, `*efibootmgr*`, `*bcdedit*`, `*diskpart*`, `*format-volume*`, `*cryptsetup*`, `*dislocker*`, `*ntfsfix*`, `*chkdsk*`, `*fsck*`, `*rescue.env*`, `*hermes/env*`, `*rescue_github_issues_token*`, `*malware-detections-*`, `*/quarantine/*`, `rm -rf *`, `*remove-item*-recurse*`. Diverifikasi terhadap checkout Hermes lokal (`hermes config check` dan `tools.approval._match_user_deny_rule`); tesnya dilewati bersih bila Hermes tidak ada (CI) | Implemented; sesi Hermes nyata Hardware-required |

### Follow-up bertipe (`scripts/rescue-followup.py`)

```
rescue-followup.py --evidence FILE --reports-dir DIR [--mode live-linux|linux-host] [--state-dir DIR] [--timeout SECONDS]
```

Menulis `DIR/followup-<run_id>.json` secara atomik (0600 bila didukung; dari `sudo -n` berkas diserahkan ke pengguna desktop) dan mencetak ringkasan dua bahasa. Exit 0 walau ada item `unknown`; 2 untuk input atau evidence tidak valid (atau `--timeout` di luar 10 sampai 900 detik, default 120 detik total, tiap perintah dengan batas sendiri). Mode bawaan diambil dari `source_platform`; `windows-host` ditulis native oleh launcher Windows dan ditolak di sini. Resep tetap dan hanya untuk check berstatus warn/fail/unknown dalam scope:

| Check | Follow-up | Isi (angka/boolean/enum saja) |
|---|---|---|
| `smart-health`, `nvme-health` | `disk.attributes`, `disk.selftest-result` per `disk-N` (urutan disk internal dari `lsblk`; tanpa serial, model, atau path) via `smartctl -j` | realokasi, pending, offline-uncorrectable, jam hidup, suhu, NVMe percentage used/media errors/critical warning/spare; self-test terakhir `completed-ok`, `in-progress` (persen tersisa), `failed`, `aborted`, `none` |
| `linux-journal-errors` | `journal.categories` (host: `journalctl -p 3 -b -o json`; live: jurnal `var/log/journal` target Linux yang di-mount read-only, tanpa symlink keluar root) | hitungan per 13 kategori tetap (`kernel`, `storage`, `filesystem`, `network`, `display-gpu`, `audio`, `usb`, `bluetooth`, `power-acpi`, `systemd`, `security-auth`, `application`, `other`) lewat pemetaan allowlist internal; tanpa teks pesan, unit, atau nama program |
| `malware-scan`, `malware-signatures` | `malware.coverage`, `malware.signatures` | cakupan (`complete`, `incomplete`, `stale-signatures`, `not-scanned`, `budget-exhausted`, `detections-found`), jumlah deteksi, umur signature (hari), ada tidaknya basis data; diturunkan dari evidence dan basis data signature lewat `rescue_modules.malware`, tanpa memindai ulang |
| `persistence` (live, selalu) | `persistence.active` | `persistence_active` (tidak ada bila tidak dapat ditentukan), `upper_backing` (`block`, `loop`, `tmpfs`, `unknown`), `cmdline_persistent`; dari `/proc/mounts` dan `/proc/cmdline`: lapisan tulis overlay di perangkat blok/loop ber-filesystem ext/btrfs/xfs berarti aktif, di `tmpfs` berarti tidak (keberadaan `/cow` saja bukan bukti) |

Aturan: `unknown` tidak pernah menjadi `pass` (alat hilang `tool-missing`, tanpa root `needs-root`, waktu habis `timeout`, target tidak bisa di-mount `not-mounted`). Di mode `linux-host` yang berjalan sebagai pengguna biasa, apa pun yang butuh root menjadi `unknown`/`needs-root`; ini wajar, bukan kerusakan. Format (`rescue-ai/v1/followup.schema.json`, `schema_version` `1.0`): `run_id`, `mode` (`live-linux`, `linux-host`, `windows-host`), `generated_at`, `items[]` berisi `check_id`, `target_ref` (opsional: `os-N`, `disk-N`), `followup_id`, `status`, `reason` (himpunan tertutup) dan `values` (nama tetap; angka, boolean, atau anggota enum tertutup). **Privacy self-check** menolak dan tidak menulis dokumen yang berisi kunci atau nilai di luar himpunan itu, atau string yang menyerupai path, serial, MAC/IP, e-mail, atau teks bebas; skema yang sama dipakai launcher Windows (**Planned**) saat menulis berkas native.

## Konfigurasi Hermes pada USB

```mermaid
flowchart LR
    USB[USB writable state] --> H[Isolated HERMES_HOME]
    H --> S[Sanitized skills and memory]
    H --> A[Approval policy]
    A --> G[OpenCode Go]
    H -. no personal profile .-> P[Operator ~/.hermes]
```

- Gunakan profile Hermes khusus rescue, bukan profile personal.
- `config/hermes-rescue.config.yaml` menetapkan `approvals.mode: manual` dan daftar `approvals.deny` ([Autorun Hermes](#autorun-hermes-69)): perintah di daftar itu diblokir walau Hermes dijalankan dengan `--yolo`.
- Set `HERMES_HOME` ke partisi writable terenkripsi atau media penyimpanan terpisah.
- Nonaktifkan channel messaging dan webhook pada mode rescue kecuali operator mengaktifkannya secara eksplisit (**Planned**: template config saat ini belum menetapkannya; jangan mengaktifkan channel di profil rescue).
- Aktifkan memory/skills hanya untuk data yang sudah disanitasi.
- Provider utama: OpenCode Go melalui adapter resmi yang dikonfigurasi operator.
- `.env` lokal yang di-ignore dapat dipakai oleh preparation helper untuk memprovision hanya `OPENCODE_GO_API_KEY` ke `config/rescue.env` pada USB (mode `0600` diminta); helper tidak mengeksekusi isi dotenv, dan salinan bundle rescue memakai allowlist sehingga `.env` tidak pernah ikut tertulis. Skrip runtime membaca `config/rescue.env` dan `<state-dir>/hermes/env` lewat `scripts/lib/rescue-env.sh` (hanya key allowlist, tidak pernah dieksekusi sebagai shell). Gunakan `--no-provision-secrets` bila key tidak boleh ada di USB.
- Installer Hermes membuat autostart XFCE default dengan `--hardware-mode auto`, memakai state writable yang sudah dipasang.
- Jika internet/provider gagal, Hermes tetap menjalankan collector dan membuat laporan `manual_intervention`.
- Toolset default hanya `rescue_read_only`; tool mutating berada pada toolset terpisah dan selalu membutuhkan approval (**Planned**; hari ini mutasi hanya lewat mesin perbaikan katalog dengan persetujuan operator).
- Gunakan checkpoint sebelum tindakan yang disetujui dan lakukan read-back sesudahnya (**Implemented** di mesin perbaikan: `--backup-ref`, langkah `verify`, rollback, journal).

Jangan menyalin seluruh `~/.hermes` dari komputer utama ke USB. Gunakan profile terpisah agar session, memory, credential, dan skill personal tidak bocor silang.

## Kontrak tool (Planned)

Kontrak `tool_id` di bawah adalah rancangan. Kontrak yang berlaku hari ini untuk mutasi adalah katalog aksi bertipe ([repair-framework.md](repair-framework.md)).

```mermaid
sequenceDiagram
    participant H as Hermes
    participant A as Typed adapter
    participant K as Allowlist
    participant E as Evidence store
    H->>K: Request tool_id
    K-->>A: Resolve fixed executable
    A->>E: Record exit status and hash
    E-->>H: Structured result
```

Setiap adapter tool mengembalikan struktur:

```json
{
  "tool_id": "filesystem-discovery",
  "request_id": "req-20260929-0001",
  "mode": "read_only",
  "target_opaque_id": "target-abc123",
  "started_at": "2026-09-29T10:30:00Z",
  "finished_at": "2026-09-29T10:30:01Z",
  "exit_class": "success",
  "evidence_refs": ["ev-0001"],
  "sha256": "..."
}
```

Hermes tidak boleh membuat `tool_id` atau `command` baru dari output model. Controller memetakan `tool_id` ke executable yang sudah dipaketkan dan checksum-nya dicatat di release manifest.

## Evaluasi kecerdasan

```mermaid
flowchart TD
    C[Case outcomes] --> M[Metrics]
    M --> R[Regression corpus]
    R --> D{Release improves safety?}
    D -- yes --> P[Promote skill]
    D -- no --> B[Block and revise]
```

Jangan memakai “jawaban model terlihat pintar” sebagai metrik. Ukur:

- `diagnosis_precision`: proporsi hipotesis yang dikonfirmasi operator;
- `safe_next_check_rate`: usulan berikutnya valid, read-only, dan allowlisted;
- `unsafe_suggestion_rate`: saran yang melanggar policy;
- `verification_success_rate`: tindakan yang benar-benar terverifikasi;
- `false_repair_rate`: perubahan yang memperburuk atau tidak menyelesaikan masalah;
- `time_to_first_useful_evidence`;
- `provider_failure_rate`;
- `repeat_case_resolution_rate` setelah skill dipromosikan.

Sediakan dataset regresi anonim berisi signature dan expected safe checks, bukan raw disk data. Jalankan evaluasi setiap kali skill bundle atau prompt policy berubah.

## Contoh loop operasional

```mermaid
sequenceDiagram
    participant PC as Live PC
    participant R as Rescue OMES
    participant H as Hermes
    participant G as OpenCode Go
    participant Op as Operator
    PC->>R: Boot and collect
    R->>H: Sanitized case signature
    H->>G: Facts and bounded evidence
    G-->>H: Hypotheses and read-only checks
    H->>Op: Request approval
    Op-->>R: Approve check
    R-->>H: Verified result
    H-->>Op: Final report and feedback label
```

1. Boot USB Linux Mint XFCE.
2. Rescue OMES memeriksa checksum media, environment, network, dan tool manifest.
3. Hermes membuat `case_signature` dari evidence awal.
4. Hermes mengambil playbook yang sudah disetujui.
5. OpenCode Go menerima ringkasan tersanitasi dan diminta mengembalikan:
   - fakta;
   - hipotesis berperingkat;
   - evidence yang masih kurang;
   - check read-only berikutnya;
   - kondisi berhenti.
6. Operator menyetujui check berikutnya.
7. Controller menjalankan adapter typed, bukan command dari model.
8. Hermes memperbarui diagnosis.
9. Jika repair diperlukan, mesin perbaikan menampilkan kartu per aksi (asal usulan, risiko, rollback), meminta backup/image reference untuk aksi `destructive`, dan meminta persetujuan operator (**Implemented**).
10. Setelah tindakan, langkah `verify` membaca ulang state, launcher memindai ulang, dan laporan proses mencatat hasilnya (**Implemented**); `verification.json` adalah rancangan (**Planned**).
11. Operator memberi label hasil.
12. Learning curator membuat candidate playbook; promosi dilakukan setelah evaluasi dan approval.

## Risiko utama dan mitigasi

```mermaid
flowchart TD
    I[Untrusted input] --> S[Sanitization]
    S --> P[Policy gate]
    P --> A[Approval]
    A --> V[Verification]
    I -. poisoning .-> B[Block promotion]
    I -. credential .-> C[Secret redaction]
```

- **Memory poisoning:** hanya evidence yang disanitasi dan feedback terverifikasi yang boleh masuk candidate store.
- **Skill drift:** setiap skill memiliki versi, checksum, author/reviewer, dan tanggal review.
- **Prompt injection dari log:** semua log diperlakukan sebagai data tidak tepercaya; model tidak boleh mengikuti instruksi yang ditemukan dalam log.
- **Credential leakage:** credentials hanya di credential store/provider; tidak pernah ditulis ke case atau prompt artifact.
- **False confidence:** Hermes wajib membedakan fact, hypothesis, unknown, dan verified outcome.
- **Offline failure:** diagnosis tetap berjalan secara lokal; AI status berubah menjadi `manual_intervention`.
- **USB compromise:** signed manifest, checksum, encrypted writable partition, dan release rollback.
- **Overfitting:** skill baru diuji pada kasus lama dan kasus sintetis sebelum promosi.

## Roadmap implementasi

```mermaid
flowchart LR
    F1[Fase 1: Fondasi] --> F2[Fase 2: Closed loop]
    F2 --> F3[Fase 3: Evaluasi dan distribusi]
    F3 --> R[Release bundle bertanda tangan]
```

### Fase 1 — fondasi

```mermaid
flowchart TD
    P[Profile] --> T[Typed tools]
    T --> L[Encrypted ledger]
    L --> G[OpenCode Go adapter]
```
- [x] profile `rescue-hermes` terpisah;
- [x] typed read-only collectors dan aksi katalog bertipe (pengganti adapter `tool_id`);
- [ ] case/feedback/verification schemas;
- [ ] local encrypted ledger (journal berantai hash sudah ada, belum terenkripsi);
- [x] OpenCode Go analyzer dengan timeout dan sanitization.

### Fase 2 — closed learning loop

```mermaid
flowchart LR
    C[Case] --> F[Feedback]
    F --> M[Candidate memory]
    M --> S[Candidate skill]
    S --> E[Regression evaluation]
```
- [ ] case signature dan retrieval;
- [ ] candidate memory writer;
- [ ] candidate skill generator;
- [ ] operator feedback command;
- [ ] promotion gate dan rollback.

### Fase 3 — evaluasi berkelanjutan

```mermaid
flowchart TD
    E[Anonymous regression corpus] --> S[Release scorecard]
    S --> C[Curator review]
    C --> B[Signed bundle distribution]
    B --> H[Hardware matrix]
```
- [ ] regression corpus anonim;
- [ ] scorecard per release;
- [ ] skill curator terjadwal ketika USB online;
- [ ] signed bundle distribution;
- [ ] hardware lab matrix Pi 5/PC x86, SATA/NVMe, UEFI/BIOS.

## Keputusan desain

```mermaid
flowchart LR
    M[Memory terkurasi] --> I[Improved retrieval]
    S[Skill teruji] --> I
    F[Feedback terverifikasi] --> I
    I --> D[Diagnosis lebih aman]
    D -. no unreviewed self-modification .-> X[Control boundary]
```

Solusi ini membuat Hermes semakin cerdas terutama melalui **retrieval, memory terkurasi, skill yang terbukti, dan feedback terverifikasi**. Fine-tuning model OpenCode Go tidak diasumsikan tersedia atau diperlukan. Ini lebih aman, dapat diaudit, bisa berjalan offline untuk collection, dan mencegah satu diagnosis keliru menyebar menjadi aturan permanen.

## Referensi

```mermaid
flowchart TD
    H[Hermes docs] --> P[Provider and memory rules]
    O[OpenCode docs] --> G[Provider/model contract]
    V[Ventoy docs] --> U[USB boot workflow]
    L[Linux Mint docs] --> I[ISO verification]
```

- [Hermes Agent documentation index](https://hermes-agent.nousresearch.com/docs/llms.txt)
- [Hermes persistent memory](https://hermes-agent.nousresearch.com/docs/user-guide/features/memory?full=true)
- [Hermes skills system](https://hermes-agent.nousresearch.com/docs/user-guide/features/skills?full=true)
- [Hermes security](https://hermes-agent.nousresearch.com/docs/user-guide/security?full=true)
- [OpenCode Go](https://opencode.ai/docs/go)
