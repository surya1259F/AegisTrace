#!/usr/bin/env python3
import os
import subprocess
from pathlib import Path

def create_synthetic_disk_image(target_path: Path) -> Path:
    """
    Creates a deterministic, non-sensitive 1MB FAT filesystem image
    containing allocated files and deleted files for Sleuth Kit fls testing.
    """
    target_path.parent.mkdir(parents=True, exist_ok=True)
    
    # 1. Create 1MB zeroed file
    with open(target_path, "wb") as f:
        f.write(b"\x00" * (1024 * 1024))

    # 2. Format as VFAT
    mkfs_vfat = subprocess.run(["which", "mkfs.vfat"], capture_output=True, text=True).stdout.strip()
    if not mkfs_vfat:
        raise RuntimeError("mkfs.vfat not found on system.")

    subprocess.run([mkfs_vfat, str(target_path)], check=True, capture_output=True)

    # 3. Inject standard FAT directory entries directly into root directory sector
    with open(target_path, "r+b") as f:
        f.seek(0)
        boot = f.read(512)
        bytes_per_sec = int.from_bytes(boot[11:13], 'little')
        reserved_sec = int.from_bytes(boot[14:16], 'little')
        num_fats = boot[16]
        fat_size = int.from_bytes(boot[22:24], 'little')
        
        root_offset = (reserved_sec + (num_fats * fat_size)) * bytes_per_sec
        
        # Entry 1: Allocated file 'NORMAL.TXT'
        f.seek(root_offset)
        entry1 = b'NORMAL  TXT' + bytes([0x20]) + (b'\x00' * 10) + bytes([0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x50, 0x00, 0x00, 0x00])
        f.write(entry1)
        
        # Entry 2: Deleted file 'EVIL.BAT' (first byte 0xE5 = deleted marker)
        entry2 = bytes([0xE5]) + b'VIL    BAT' + bytes([0x20]) + (b'\x00' * 10) + bytes([0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x80, 0x00, 0x00, 0x00])
        f.write(entry2)

        # Entry 3: Allocated file 'REPORT.DOC'
        entry3 = b'REPORT  DOC' + bytes([0x20]) + (b'\x00' * 10) + bytes([0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x90, 0x00, 0x00, 0x00])
        f.write(entry3)

    return target_path

if __name__ == "__main__":
    p = Path(__file__).resolve().parent / "synthetic_disk.img"
    create_synthetic_disk_image(p)
    print(f"Created synthetic disk image: {p}")
