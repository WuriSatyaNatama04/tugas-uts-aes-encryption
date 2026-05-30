"""
==============================================
  APLIKASI ENKRIPSI FILE MENGGUNAKAN AES
  Nama    : [Wuri Satya Natama]
  NIM     : [105841118824]
  Kelas   : [4-F]
  Matkul  : Kriptografi
==============================================
"""

import os
import sys
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib


# =============================================
#   FUNGSI UTILITAS
# =============================================

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Menurunkan kunci AES 256-bit dari password menggunakan PBKDF2.
    PBKDF2 (Password-Based Key Derivation Function 2) memperkuat
    password agar tahan terhadap serangan brute-force.
    """
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    return key


def get_file_hash(filepath: str) -> str:
    """Menghitung hash SHA-256 dari sebuah file untuk verifikasi integritas."""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()


def print_separator():
    print("=" * 55)


def print_header():
    print_separator()
    print("   APLIKASI ENKRIPSI FILE MENGGUNAKAN AES-256-CBC")
    print("   Library  : pycryptodome")
    print("   Mode AES : CBC (Cipher Block Chaining)")
    print_separator()


# =============================================
#   FUNGSI ENKRIPSI
# =============================================

def encrypt_file(input_path: str, output_path: str, password: str):
    """
    Mengenkripsi file menggunakan AES-256 mode CBC.

    Struktur file terenkripsi:
    [SALT (16 bytes)] + [IV (16 bytes)] + [CIPHERTEXT]
    
    - SALT  : nilai acak untuk key derivation (PBKDF2)
    - IV    : Initialization Vector untuk mode CBC
    - CIPHERTEXT : data terenkripsi dengan padding PKCS7
    """
    print(f"\n[*] Memulai proses enkripsi...")
    print(f"    File input  : {input_path}")
    print(f"    File output : {output_path}")

    # Baca file asli
    with open(input_path, 'rb') as f:
        plaintext = f.read()

    print(f"    Ukuran file asli : {len(plaintext)} bytes")

    # Hash file sebelum enkripsi
    hash_sebelum = get_file_hash(input_path)
    print(f"    Hash (SHA-256) sebelum enkripsi:")
    print(f"    -> {hash_sebelum}")

    # Generate SALT dan IV secara acak
    salt = get_random_bytes(16)
    iv   = get_random_bytes(16)

    # Turunkan kunci dari password
    key = derive_key(password, salt)
    print(f"\n    [+] Kunci AES 256-bit berhasil diturunkan dari password.")
    print(f"    [+] Salt (hex) : {salt.hex()}")
    print(f"    [+] IV   (hex) : {iv.hex()}")

    # Enkripsi dengan AES-CBC + PKCS7 padding
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    # Tulis: SALT + IV + CIPHERTEXT
    with open(output_path, 'wb') as f:
        f.write(salt + iv + ciphertext)

    print(f"\n    [+] Enkripsi BERHASIL!")
    print(f"    Ukuran file terenkripsi : {len(salt) + len(iv) + len(ciphertext)} bytes")
    hash_sesudah = get_file_hash(output_path)
    print(f"    Hash (SHA-256) sesudah enkripsi:")
    print(f"    -> {hash_sesudah}")
    print_separator()


# =============================================
#   FUNGSI DEKRIPSI
# =============================================

def decrypt_file(input_path: str, output_path: str, password: str):
    """
    Mendekripsi file yang telah dienkripsi dengan AES-256 mode CBC.
    Membaca SALT dan IV dari header file, lalu mendekripsi CIPHERTEXT.
    """
    print(f"\n[*] Memulai proses dekripsi...")
    print(f"    File input  : {input_path}")
    print(f"    File output : {output_path}")

    # Baca file terenkripsi
    with open(input_path, 'rb') as f:
        data = f.read()

    # Pisahkan SALT (16 bytes), IV (16 bytes), dan CIPHERTEXT
    salt       = data[:16]
    iv         = data[16:32]
    ciphertext = data[32:]

    print(f"    [+] Salt (hex) : {salt.hex()}")
    print(f"    [+] IV   (hex) : {iv.hex()}")
    print(f"    [+] Ukuran ciphertext : {len(ciphertext)} bytes")

    # Turunkan kunci dari password + salt yang sama
    key = derive_key(password, salt)

    try:
        # Dekripsi dengan AES-CBC
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

        # Tulis hasil dekripsi
        with open(output_path, 'wb') as f:
            f.write(plaintext)

        print(f"\n    [+] Dekripsi BERHASIL!")
        print(f"    Ukuran file hasil dekripsi : {len(plaintext)} bytes")
        hash_hasil = get_file_hash(output_path)
        print(f"    Hash (SHA-256) file hasil dekripsi:")
        print(f"    -> {hash_hasil}")
        print_separator()

    except (ValueError, KeyError):
        print("\n    [!] GAGAL! Password salah atau file rusak.")
        print_separator()


# =============================================
#   MENU UTAMA
# =============================================

def main():
    print_header()

    print("\nPilih operasi:")
    print("  1. Enkripsi File")
    print("  2. Dekripsi File")
    print("  3. Demo Otomatis (buat file TXT contoh, enkripsi, lalu dekripsi)")

    pilihan = input("\nMasukkan pilihan (1/2/3): ").strip()

    if pilihan == "1":
        input_path  = input("Masukkan path file yang akan dienkripsi: ").strip()
        output_path = input("Masukkan path file output (.enc): ").strip()
        password    = input("Masukkan password/kunci enkripsi: ").strip()
        encrypt_file(input_path, output_path, password)

    elif pilihan == "2":
        input_path  = input("Masukkan path file terenkripsi (.enc): ").strip()
        output_path = input("Masukkan path file output hasil dekripsi: ").strip()
        password    = input("Masukkan password/kunci dekripsi: ").strip()
        decrypt_file(input_path, output_path, password)

    elif pilihan == "3":
        print("\n[DEMO OTOMATIS]")
        print_separator()

        # Buat file TXT contoh
        demo_txt = "file_demo_aes.txt"
        demo_enc = "file_demo_aes.enc"
        demo_dec = "file_demo_aes_HASIL.txt"
        password = "passwordRahasia123"

        isi_file = (
            "Ini adalah file demo untuk UTS Kriptografi.\n"
            "Aplikasi enkripsi file menggunakan AES-256-CBC.\n"
            "Library yang digunakan: pycryptodome\n"
            "AES (Advanced Encryption Standard) adalah algoritma\n"
            "kriptografi simetris standar internasional (NIST).\n"
        )

        with open(demo_txt, 'w') as f:
            f.write(isi_file)

        print(f"\n[+] File TXT demo dibuat: {demo_txt}")
        print(f"    Isi file:\n")
        print("    " + isi_file.replace('\n', '\n    '))

        # Enkripsi
        encrypt_file(demo_txt, demo_enc, password)

        # Tampilkan isi file terenkripsi (beberapa byte pertama)
        with open(demo_enc, 'rb') as f:
            enc_bytes = f.read(48)
        print(f"\n[+] Preview file terenkripsi (48 bytes pertama, hex):")
        print(f"    {enc_bytes.hex()}")
        print()

        # Dekripsi
        decrypt_file(demo_enc, demo_dec, password)

        # Tampilkan isi hasil dekripsi
        with open(demo_dec, 'r') as f:
            hasil = f.read()
        print(f"\n[+] Isi file hasil dekripsi ({demo_dec}):")
        print("    " + hasil.replace('\n', '\n    '))

        # Verifikasi integritas
        hash_asli  = get_file_hash(demo_txt)
        hash_hasil = get_file_hash(demo_dec)
        print("\n[VERIFIKASI INTEGRITAS]")
        print_separator()
        print(f"  Hash file ASLI   : {hash_asli}")
        print(f"  Hash file HASIL  : {hash_hasil}")
        if hash_asli == hash_hasil:
            print("  STATUS: IDENTIK - Integritas file terjaga! ✓")
        else:
            print("  STATUS: BERBEDA - File rusak atau password salah! ✗")
        print_separator()

    else:
        print("Pilihan tidak valid.")


if __name__ == "__main__":
    main()