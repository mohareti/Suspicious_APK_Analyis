import zipfile
import struct

def analyze_zip_encryption(zip_path):
    with open(zip_path, 'rb') as f:
        data = f.read()

    def find_encrypted_files(data):
        offset = 0
        encrypted_files = []

        while offset < len(data):
            # Local file header signature (4 bytes): 0x04034b50
            if data[offset:offset+4] == b'PK\x03\x04':
                # Parse local file header
                flag_bits = struct.unpack('<H', data[offset+6:offset+8])[0]
                comp_method = struct.unpack('<H', data[offset+8:offset+10])[0]
                fname_len = struct.unpack('<H', data[offset+26:offset+28])[0]
                extra_len = struct.unpack('<H', data[offset+28:offset+30])[0]

                # Filename
                fname = data[offset+30:offset+30+fname_len].decode(errors='replace')

                is_encrypted = bool(flag_bits & 0x1)

                if is_encrypted:
                    encrypted_files.append({
                        'offset': offset,
                        'filename': fname,
                        'compression': comp_method,
                        'flag_bits': flag_bits
                    })

                # Move to next file header
                next_offset = offset + 30 + fname_len + extra_len
                offset = next_offset
            else:
                offset += 1

        return encrypted_files

    encrypted_files = find_encrypted_files(data)

    if encrypted_files:
        print(f"🔒 Encrypted files detected ({len(encrypted_files)}):\n")
        for file in encrypted_files:
            print(f"📄 {file['filename']}")
            print(f"    ↪ Offset: 0x{file['offset']:08X}")
            print(f"    ↪ Compression Method: {file['compression']}")
            print(f"    ↪ Flag Bits: 0x{file['flag_bits']:04X}\n")
    else:
        print("✅ No encrypted files found.")

# Example usage:
apk_path = "/content/Suspicious_APK_Analyis/2025.apk"
analyze_zip_encryption(apk_path)
