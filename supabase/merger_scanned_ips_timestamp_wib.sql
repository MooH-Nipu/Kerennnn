-- Opsional: jalankan di Supabase SQL Editor bila perlu mengubah updated_at untuk data yang sudah ada.
-- Kolom updated_at bertipe timestamptz (momen absolut; UI/tool bisa menampilkan zona apa pun).
-- Waktu dengan offset WIB gunakan literal +07, contoh 15:00 WIB = 15:00 di Asia/Jakarta.

-- Semua baris → "sekarang" (momen saat query dijalankan)
-- UPDATE public.merger_scanned_ips SET updated_at = now();

-- Satu IP
-- UPDATE public.merger_scanned_ips SET updated_at = now() WHERE ip = '203.0.113.10';

-- Set ke tanggal & jam tertentu dalam WIB (+7), contoh 18 April 2026 pukul 15:30 WIB
-- UPDATE public.merger_scanned_ips
-- SET updated_at = '2026-04-18 15:30:00+07'::timestamptz
-- WHERE ip = '203.0.113.10';

-- Banyak IP sekaligus (daftar IN)
-- UPDATE public.merger_scanned_ips
-- SET updated_at = '2026-04-18 15:30:00+07'::timestamptz
-- WHERE ip IN ('203.0.113.10', '198.51.100.2');
