#!/usr/bin/env node

/**
 * ============================================================================
 * Storage Audit CLI Tool (storage_audit.js)
 * ============================================================================
 * Utilitas command-line audit penyimpanan tanpa dependensi eksternal (zero-dep)
 * Menggunakan modul bawaan Node.js: fs, path, crypto, readline.
 *
 * Fitur:
 * - STG-01: Recursive Scan (pemindaian mendalam & pembuatan hash SHA-256)
 * - STG-02: Duplicate Detection (pengelompokan file dengan hash identik)
 * - STG-03: Giant File Flagging (ambang batas >= 2 MB / 2.048 KB)
 * - STG-04: Terminal Report (laporan terstruktur di stdout)
 * - STG-05: Safe Cleanup Confirmation (prompt interaktif Y/N yang aman)
 * - STG-06: Zero-Dependency Portability (hanya modul native Node.js)
 * ============================================================================
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');

// Konfigurasi Ambang Batas
const GIANT_FILE_THRESHOLD_BYTES = 2 * 1024 * 1024; // 2 MB = 2.048 KB = 2.097.152 bytes

// Format ANSI Colors untuk output terminal yang profesional dan rapi
const colors = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  italic: '\x1b[3m',
  underline: '\x1b[4m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  cyan: '\x1b[36m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  gray: '\x1b[90m',
  bgBlue: '\x1b[44m',
  bgRed: '\x1b[41m',
  bgGreen: '\x1b[42m',
};

// Helper: Format Ukuran Byte ke String yang Mudah Dibaca
function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Helper: Format Ukuran Khusus dalam MB dan KB
function formatMBandKB(bytes) {
  const mb = (bytes / (1024 * 1024)).toFixed(2);
  const kb = (bytes / 1024).toLocaleString('id-ID', { maximumFractionDigits: 2 });
  return `${mb} MB (${kb} KB)`;
}

// Helper: Menghitung Hash SHA-256 menggunakan stream
function getFileHash(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', (data) => hash.update(data));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', (err) => reject(err));
  });
}

// Helper: Memberi skor pada nama file untuk menentukan file ASLI vs SALINAN
// Skor lebih rendah = lebih besar kemungkinan merupakan file asli
function scoreOriginal(fileName) {
  let penalty = 0;
  const lower = fileName.toLowerCase();

  if (/ - copy/i.test(lower)) penalty += 1000;
  if (/ - salinan/i.test(lower)) penalty += 1000;
  if (/ \(\d+\)/.test(lower)) penalty += 500;
  if (/_copy/i.test(lower)) penalty += 500;
  if (/_backup/i.test(lower)) penalty += 500;
  if (/_v\d+/i.test(lower)) penalty += 400;
  if (/_edit\d*/i.test(lower)) penalty += 300;
  if (/_final/i.test(lower)) penalty += 200;
  if (/_fix/i.test(lower)) penalty += 200;

  // Nama lebih pendek biasanya merupakan nama asli/induk
  penalty += lower.length;
  return penalty;
}

// STG-01: Recursive Scan
async function scanDirectory(dirPath, rootDir, visitedInodes = new Set()) {
  const fileList = [];
  let entries;

  try {
    entries = fs.readdirSync(dirPath, { withFileTypes: true });
  } catch (err) {
    console.error(`${colors.red}[ERROR] Gagal membaca direktori: ${dirPath} (${err.message})${colors.reset}`);
    return fileList;
  }

  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry.name);
    const relativePath = path.relative(rootDir, fullPath);

    // Lewati folder .git, node_modules, dan skrip audit itu sendiri
    if (entry.name === '.git' || entry.name === 'node_modules') continue;
    if (entry.name === 'storage_audit.js' || entry.name === 'storage_audit.py') continue;

    try {
      const stats = fs.statSync(fullPath);

      // Pencegahan loop rekursif untuk symlink / junction
      const inodeKey = `${stats.dev}:${stats.ino}`;
      if (visitedInodes.has(inodeKey)) continue;
      visitedInodes.add(inodeKey);

      if (stats.isDirectory()) {
        const subFiles = await scanDirectory(fullPath, rootDir, visitedInodes);
        fileList.push(...subFiles);
      } else if (stats.isFile()) {
        const hash = await getFileHash(fullPath);
        fileList.push({
          name: entry.name,
          fullPath,
          relativePath: relativePath || entry.name,
          size: stats.size,
          hash,
          isGiant: stats.size >= GIANT_FILE_THRESHOLD_BYTES,
          isTmp: entry.name.toLowerCase().endsWith('.tmp') || entry.name.toLowerCase().endsWith('.temp'),
        });
      }
    } catch (err) {
      console.warn(`${colors.yellow}[PERINGATAN] Dilewati (${entry.name}): ${err.message}${colors.reset}`);
    }
  }

  return fileList;
}

// STG-02: Duplicate Detection
function detectDuplicates(files) {
  const groupsByHash = {};

  for (const file of files) {
    if (!groupsByHash[file.hash]) {
      groupsByHash[file.hash] = [];
    }
    groupsByHash[file.hash].push(file);
  }

  const duplicateGroups = [];
  for (const [hash, groupFiles] of Object.entries(groupsByHash)) {
    if (groupFiles.length > 1) {
      // Urutkan file: file dengan penalti terendah menjadi file ASLI (pertama)
      const sorted = [...groupFiles].sort((a, b) => scoreOriginal(a.name) - scoreOriginal(b.name));
      const original = sorted[0];
      const duplicates = sorted.slice(1);

      duplicateGroups.push({
        hash,
        size: original.size,
        totalFiles: sorted.length,
        original,
        duplicates,
        allFiles: sorted,
      });
    }
  }

  return duplicateGroups;
}

// STG-03: Giant File Flagging
function getGiantFiles(files) {
  return files
    .filter((f) => f.isGiant)
    .sort((a, b) => b.size - a.size); // Urutkan terbesar ke terkecil
}

// STG-04: Terminal Report
function printReport(targetDir, files, giantFiles, duplicateGroups, tmpFiles) {
  const totalSizeBytes = files.reduce((acc, f) => acc + f.size, 0);

  // Hitung estimasi ruang yang bisa dihemat dari duplikat + file .tmp
  let potentialSavingsBytes = 0;
  let totalDuplicatesCount = 0;

  for (const grp of duplicateGroups) {
    potentialSavingsBytes += grp.size * grp.duplicates.length;
    totalDuplicatesCount += grp.duplicates.length;
  }

  // Tambahkan file .tmp yang bukan bagian dari grup duplikat yang sudah dihitung
  for (const tmp of tmpFiles) {
    const alreadyCounted = duplicateGroups.some((grp) =>
      grp.duplicates.some((dup) => dup.fullPath === tmp.fullPath)
    );
    if (!alreadyCounted) {
      potentialSavingsBytes += tmp.size;
    }
  }

  const divider = '─'.repeat(78);
  const doubleDivider = '═'.repeat(78);

  console.log(`\n${colors.cyan}${colors.bold}${doubleDivider}`);
  console.log(`         LAPORAN AUDIT PENYIMPANAN SISTEM (STORAGE AUDIT CLI)         `);
  console.log(`${doubleDivider}${colors.reset}\n`);

  // Ringkasan Umum
  console.log(`${colors.bold}📌 RINGKASAN PEMINDAIAN FOLDER:${colors.reset}`);
  console.log(`   • Folder Target       : ${colors.yellow}${targetDir}${colors.reset}`);
  console.log(`   • Total File Terpindai: ${colors.green}${colors.bold}${files.length}${colors.reset} file`);
  console.log(`   • Total Ukuran Folder : ${colors.green}${colors.bold}${formatBytes(totalSizeBytes)}${colors.reset} (${totalSizeBytes.toLocaleString('id-ID')} bytes)`);
  console.log(`   • Ambang Batas Giant  : ${colors.magenta}2 MB (2.048 KB)${colors.reset}`);
  console.log(`${colors.gray}${divider}${colors.reset}\n`);

  // STG-03: Laporan File Raksasa (Giant Files)
  console.log(`${colors.bold}🐘 [STG-03] DAFTAR FILE RAKSASA (Ukuran >= 2 MB):${colors.reset}`);
  if (giantFiles.length === 0) {
    console.log(`   ${colors.gray}(Tidak ditemukan file raksasa)${colors.reset}`);
  } else {
    console.log(`   Ditemukan ${colors.yellow}${colors.bold}${giantFiles.length}${colors.reset} file raksasa:\n`);
    giantFiles.forEach((file, idx) => {
      const num = String(idx + 1).padStart(2, ' ');
      console.log(`   [${colors.cyan}${num}${colors.reset}] ${colors.bold}${file.name}${colors.reset}`);
      console.log(`        Ukuran : ${colors.magenta}${formatMBandKB(file.size)}${colors.reset}`);
      console.log(`        Lokasi : ${colors.gray}${file.relativePath}${colors.reset}`);
    });
  }
  console.log(`${colors.gray}${divider}${colors.reset}\n`);

  // STG-02: Laporan Kelompok Duplikat
  console.log(`${colors.bold}👥 [STG-02] DAFTAR KELOMPOK FILE DUPLIKAT (Identik SHA-256):${colors.reset}`);
  if (duplicateGroups.length === 0) {
    console.log(`   ${colors.gray}(Tidak ditemukan file duplikat)${colors.reset}`);
  } else {
    console.log(`   Ditemukan ${colors.yellow}${colors.bold}${duplicateGroups.length}${colors.reset} kelompok duplikat (${totalDuplicatesCount} salinan terdeteksi):\n`);
    duplicateGroups.forEach((grp, idx) => {
      const grpNum = String(idx + 1).padStart(2, ' ');
      const shortHash = grp.hash.substring(0, 16) + '...';
      console.log(`   ${colors.yellow}┌─ Grup #${grpNum}${colors.reset} [Hash: ${colors.dim}${shortHash}${colors.reset} | Ukuran per file: ${formatBytes(grp.size)}]`);
      console.log(`   │  ${colors.green}✔ [ASLI/SIMPAN]${colors.reset}  : ${grp.original.name}`);
      grp.duplicates.forEach((dup) => {
        console.log(`   │  ${colors.red}✘ [SALINAN/HAPUS]${colors.reset}: ${dup.name}`);
      });
      console.log(`   ${colors.yellow}└──────────────────────────────────────────────────────────${colors.reset}`);
    });
  }
  console.log(`${colors.gray}${divider}${colors.reset}\n`);

  // File Sampah (.tmp)
  if (tmpFiles.length > 0) {
    console.log(`${colors.bold}🗑️ DAFTAR FILE SAMPAH (.tmp / .temp):${colors.reset}`);
    tmpFiles.forEach((tmp, idx) => {
      console.log(`   [${idx + 1}] ${tmp.name} (${formatBytes(tmp.size)})`);
    });
    console.log(`${colors.gray}${divider}${colors.reset}\n`);
  }

  // Estimasi Hemat Ruang
  console.log(`${colors.bold}💡 ESTIMASI PENGHEMATAN RUANG PENYIMPANAN:${colors.reset}`);
  console.log(`   • Salinan Duplikat yang Dapat Dihapus : ${colors.yellow}${totalDuplicatesCount}${colors.reset} file`);
  if (tmpFiles.length > 0) {
    console.log(`   • File Sampah Sementara (.tmp)       : ${colors.yellow}${tmpFiles.length}${colors.reset} file`);
  }
  console.log(`   • Potensi Ruang yang Dapat Dihemat   : ${colors.green}${colors.bold}${formatBytes(potentialSavingsBytes)}${colors.reset} (${potentialSavingsBytes.toLocaleString('id-ID')} bytes / ~${(potentialSavingsBytes / (1024 * 1024)).toFixed(2)} MB)`);
  console.log(`${colors.cyan}${colors.bold}${doubleDivider}${colors.reset}\n`);

  return {
    potentialSavingsBytes,
    totalDuplicatesCount,
  };
}

// STG-05: Safe Cleanup Confirmation
async function handleCleanupPrompt(duplicateGroups, tmpFiles, autoYes = false, isDryRun = false) {
  const itemsToDelete = [];

  // Tambahkan semua file salinan duplikat
  for (const grp of duplicateGroups) {
    for (const dup of grp.duplicates) {
      itemsToDelete.push({
        name: dup.name,
        fullPath: dup.fullPath,
        size: dup.size,
        type: 'Salinan Duplikat',
      });
    }
  }

  // Tambahkan file .tmp yang belum ada di daftar
  for (const tmp of tmpFiles) {
    if (!itemsToDelete.some((item) => item.fullPath === tmp.fullPath)) {
      itemsToDelete.push({
        name: tmp.name,
        fullPath: tmp.fullPath,
        size: tmp.size,
        type: 'File Sampah (.tmp)',
      });
    }
  }

  if (itemsToDelete.length === 0) {
    console.log(`${colors.green}✔ Direktori bersih. Tidak ada file duplikat atau file sampah yang perlu dibersihkan.${colors.reset}\n`);
    return;
  }

  if (isDryRun) {
    console.log(`${colors.yellow}[DRY-RUN MODE] Simulasi penghapusan aman tanpa menghapus file fisik:${colors.reset}`);
    itemsToDelete.forEach((item, idx) => {
      console.log(`  [SIMULASI ${idx + 1}] Akan dihapus: ${item.name} (${formatBytes(item.size)})`);
    });
    console.log(`\n${colors.green}✔ Simulasi selesai. Tidak ada file yang diubah.${colors.reset}\n`);
    return;
  }

  let answer = '';

  if (autoYes) {
    answer = 'y';
    console.log(`${colors.yellow}Mode otomatis (--yes) aktif. Memulai pembersihan...${colors.reset}`);
  } else {
    // Prompt konfirmasi interaktif sesuai kebutuhan STG-05
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    answer = await new Promise((resolve) => {
      rl.question(
        `${colors.bold}${colors.yellow}Apakah kamu ingin menghapus file duplikat yang tidak terpakai? (Y/N): ${colors.reset}`,
        (res) => {
          rl.close();
          resolve(res.trim().toLowerCase());
        }
      );
    });
  }

  if (answer === 'y' || answer === 'ya' || answer === 'yes') {
    console.log(`\n${colors.cyan}Memulai proses pembersihan aman...${colors.reset}`);
    let deletedCount = 0;
    let freedBytes = 0;
    let failedCount = 0;

    for (const item of itemsToDelete) {
      try {
        if (fs.existsSync(item.fullPath)) {
          fs.unlinkSync(item.fullPath);
          deletedCount++;
          freedBytes += item.size;
          console.log(`  ${colors.green}✔ Dihapus:${colors.reset} ${item.name} ${colors.gray}(${formatBytes(item.size)})${colors.reset}`);
        } else {
          console.log(`  ${colors.yellow}⚠ File tidak ditemukan (sudah terhapus):${colors.reset} ${item.name}`);
        }
      } catch (err) {
        failedCount++;
        console.error(`  ${colors.red}✘ Gagal menghapus:${colors.reset} ${item.name} - ${err.message}`);
      }
    }

    console.log(`\n${colors.green}${colors.bold}═══ HASIL PEMBERSIHAN AMAN ═══${colors.reset}`);
    console.log(`✔ Berhasil menghapus : ${colors.green}${colors.bold}${deletedCount}${colors.reset} file`);
    if (failedCount > 0) {
      console.log(`✘ Gagal menghapus    : ${colors.red}${colors.bold}${failedCount}${colors.reset} file`);
    }
    console.log(`✔ Ruang dibebaskan   : ${colors.cyan}${colors.bold}${formatBytes(freedBytes)}${colors.reset} (${freedBytes.toLocaleString('id-ID')} bytes)`);
    console.log(`✔ 1 file asli per grup duplikat tetap aman dipertahankan.\n`);
  } else {
    console.log(`\n${colors.green}Pembersihan dibatalkan secara aman. Tidak ada file yang dihapus.${colors.reset}\n`);
  }
}

// Resolusi Folder Target
function resolveTargetFolder(rawArg) {
  if (rawArg && rawArg !== '--yes' && rawArg !== '-y' && rawArg !== '--dry-run' && rawArg !== '-d' && rawArg !== '--help' && rawArg !== '-h') {
    // 1. Cek langsung path yang diberikan
    if (fs.existsSync(rawArg)) {
      return path.resolve(rawArg);
    }
    // 2. Cek apakah ada di direktori parent
    const parentPath = path.resolve('..', rawArg);
    if (fs.existsSync(parentPath)) {
      return parentPath;
    }
    // 3. Cek di direktori Downloads standar
    const downloadsCheck = path.resolve('C:\\Users\\Student\\Downloads', rawArg);
    if (fs.existsSync(downloadsCheck)) {
      return downloadsCheck;
    }
  }

  // Jika tidak ada argumen atau mencari "Bahan Latihan P12"
  const defaultTargets = [
    path.resolve('Bahan Latihan P12'),
    path.resolve('..', 'Bahan Latihan P12'),
    path.resolve('C:\\Users\\Student\\Downloads\\Bahan Latihan P12'),
    process.cwd(),
  ];

  for (const candidate of defaultTargets) {
    if (fs.existsSync(candidate) && fs.statSync(candidate).isDirectory()) {
      return candidate;
    }
  }

  return process.cwd();
}

// Main Execution Function
async function main() {
  const args = process.argv.slice(2);

  if (args.includes('--help') || args.includes('-h')) {
    console.log(`
${colors.bold}Penggunaan:${colors.reset}
  node storage_audit.js [path_folder] [opsi]

${colors.bold}Argumen:${colors.reset}
  path_folder       Path folder target yang akan di-audit (default: "Bahan Latihan P12" atau direktori saat ini)

${colors.bold}Opsi:${colors.reset}
  -y, --yes         Otomatis menyetujui pembersihan file duplikat tanpa prompt
  -d, --dry-run     Simulasi pembersihan tanpa benar-benar menghapus file
  -h, --help        Menampilkan bantuan ini

${colors.bold}Contoh:${colors.reset}
  node storage_audit.js
  node storage_audit.js "Bahan Latihan P12"
  node storage_audit.js . --dry-run
    `);
    process.exit(0);
  }

  const isAutoYes = args.includes('--yes') || args.includes('-y');
  const isDryRun = args.includes('--dry-run') || args.includes('-d');
  const rawTargetArg = args.find((a) => !a.startsWith('-'));

  const targetDir = resolveTargetFolder(rawTargetArg);

  console.log(`${colors.cyan}Memulai pemindaian penyimpanan pada:${colors.reset} ${colors.bold}${targetDir}${colors.reset}...`);
  console.time('Waktu Pemindaian');

  // STG-01: Recursive Scan
  const scannedFiles = await scanDirectory(targetDir, targetDir);

  console.timeEnd('Waktu Pemindaian');

  if (scannedFiles.length === 0) {
    console.log(`${colors.yellow}Tidak ada file yang ditemukan untuk diaudit di direktori tersebut.${colors.reset}`);
    process.exit(0);
  }

  // STG-02: Duplicate Detection
  const duplicateGroups = detectDuplicates(scannedFiles);

  // STG-03: Giant File Flagging
  const giantFiles = getGiantFiles(scannedFiles);

  // File sementara
  const tmpFiles = scannedFiles.filter((f) => f.isTmp);

  // STG-04: Terminal Report
  printReport(targetDir, scannedFiles, giantFiles, duplicateGroups, tmpFiles);

  // STG-05: Safe Cleanup Confirmation
  await handleCleanupPrompt(duplicateGroups, tmpFiles, isAutoYes, isDryRun);
}

// Jalankan aplikasi
main().catch((err) => {
  console.error(`${colors.red}[FATAL ERROR] Terjadi kesalahan: ${err.message}${colors.reset}`);
  process.exit(1);
});
