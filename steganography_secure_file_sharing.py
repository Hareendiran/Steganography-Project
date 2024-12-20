# Steganography-Based Secure File Sharing System
import os
from PIL import Image
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import argparse
import base64
import secrets

# Function to encrypt data
def encrypt_data(data: bytes, password: str) -> bytes:
    salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return salt + iv + encrypted_data

# Function to decrypt data
def decrypt_data(encrypted_data: bytes, password: str) -> bytes:
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Function to embed data in an image
def embed_data(image_path: str, data: bytes, output_path: str):
    # Ensure the output directory exists
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    image = Image.open(image_path)
    image = image.convert("RGB")
    pixels = list(image.getdata())

    binary_data = ''.join(format(byte, '08b') for byte in data) + '1111111111111110'
    pixel_iter = iter(pixels)

    new_pixels = []
    for bit in binary_data:
        pixel = list(next(pixel_iter))
        pixel[0] = (pixel[0] & 0xFE) | int(bit)
        new_pixels.append(tuple(pixel))

    new_pixels += list(pixel_iter)  # Append remaining unmodified pixels
    image.putdata(new_pixels)
    image.save(output_path)
    print(f"Data embedded and saved to {output_path}")

# Function to extract data from an image
def extract_data(image_path: str) -> bytes:
    image = Image.open(image_path)
    image = image.convert("RGB")
    pixels = list(image.getdata())

    binary_data = ''
    for pixel in pixels:
        binary_data += str(pixel[0] & 1)
        if binary_data.endswith('1111111111111110'):
            break

    binary_data = binary_data[:-16]  # Remove end marker
    byte_data = int(binary_data, 2).to_bytes(len(binary_data) // 8, byteorder='big')
    return byte_data

# Command-line interface
def main():
    parser = argparse.ArgumentParser(description="Steganography-Based Secure File Sharing System")
    parser.add_argument("mode", choices=["embed", "extract"], help="Mode: embed or extract data")
    parser.add_argument("image", help="Path to the image")
    parser.add_argument("output", help="Path for output (image for embed, file for extract)")
    parser.add_argument("--data", help="Path to the file containing data to embed (required for embed)")
    parser.add_argument("--password", help="Password for encryption (optional)")

    args = parser.parse_args()

    if args.mode == "embed":
        if not args.data:
            print("Error: Data file is required for embedding.")
            return

        with open(args.data, "rb") as f:
            data = f.read()

        if args.password:
            data = encrypt_data(data, args.password)

        embed_data(args.image, data, args.output)

    elif args.mode == "extract":
        data = extract_data(args.image)

        if args.password:
            data = decrypt_data(data, args.password)

        with open(args.output, "wb") as f:
            f.write(data)
        print(f"Data extracted and saved to {args.output}")

if __name__ == "__main__":
    main()
