import time
import base64
import pickle  # <-- for serialization
from phe import paillier
from tqdm import tqdm
import math
from concurrent.futures import ProcessPoolExecutor
from functools import partial

def generate_paillier_keypair():
    return paillier.generate_paillier_keypair()

def determine_chunk_size(b64_length, max_chunks=64, min_chunk_size=1):
    """
    Decide a suitable chunk size so the total number of chunks
    does not exceed 'max_chunks'. Ensures we don't go below a
    minimum chunk size.
    """
    print("b64_length", b64_length)
    if b64_length <= min_chunk_size:
        return min_chunk_size
    chunk_size = math.ceil(b64_length / max_chunks)
    return max(chunk_size, min_chunk_size)

def encrypt_chunk(chunk, public_key):
    """
    Encrypt a single chunk using the provided public key.
    This function is defined at the top level so it can be pickled.
    """
    chunk_int = int.from_bytes(chunk.encode('utf-8'), byteorder='big')
    return public_key.encrypt(chunk_int)

def encode_and_encrypt_image(image_file, public_key, max_chunks=256):
    overall_start = time.time()
    
    # 1. Read raw bytes from the file-like object.
    t0 = time.time()
    img_data = image_file.read()
    t1 = time.time()
    print(f"[encoder] Reading image file took {t1 - t0:.4f} seconds.")

    # 2. Convert the image bytes to a Base64-encoded string
    t0 = time.time()
    b64_string = base64.b64encode(img_data).decode('utf-8')
    t1 = time.time()
    print(f"[encoder] Base64 encoding took {t1 - t0:.4f} seconds.")
    
    # 3. Determine chunk size and split the Base64 string
    b64_length = len(b64_string)
    chunk_size = determine_chunk_size(b64_length, max_chunks=max_chunks, min_chunk_size=16)
    print(f"[encoder] Chosen chunk_size = {chunk_size}")
    
    t0 = time.time()
    chunks = [b64_string[i:i + chunk_size] for i in range(0, b64_length, chunk_size)]
    t1 = time.time()
    print(f"[encoder] Splitting into {len(chunks)} chunks took {t1 - t0:.4f} seconds.")

    # 4. Encrypt each chunk in parallel using a top-level function.
    t0 = time.time()
    print("[encoder] Starting encryption in parallel...")
    # Use functools.partial to bind public_key to encrypt_chunk
    partial_encrypt = partial(encrypt_chunk, public_key=public_key)
    with ProcessPoolExecutor() as executor:
        encrypted_chunks = list(tqdm(executor.map(partial_encrypt, chunks),
                                       total=len(chunks),
                                       desc="Encrypting chunks",
                                       unit="chunk"))
    t1 = time.time()
    print(f"[encoder] Finished encryption in {t1 - t0:.4f} seconds.")

    total_time = time.time() - overall_start
    print(f"[encoder] Total encoding & encryption time: {total_time:.4f} seconds.")
    
    return encrypted_chunks

# if __name__ == "__main__":
#     # Example usage
#     image_path = "Five_Faces\\gates\\gates0.jpg"  # Use proper path separators for Windows
    
#     # 1. Generate keys
#     start_keygen = time.time()
#     pub_key, pri_key = generate_paillier_keypair()
#     end_keygen = time.time()
#     print(f"[encoder] Key generation took {end_keygen - start_keygen:.4f} seconds.")
    
#     # 2. Encrypt the image with parallel processing
#     ciphertexts = encode_and_encrypt_image(image_path, pub_key, max_chunks=256)
#     print(f"[encoder] Number of encrypted chunks: {len(ciphertexts)}")

#     # 3. Save ciphertexts + keys to disk
#     with open("encrypted_data_.pkl", "wb") as f:
#         pickle.dump({
#             "public_key": pub_key,
#             "private_key": pri_key,
#             "ciphertexts": ciphertexts
#         }, f)
#     print("[encoder] Encrypted data and keys saved to 'encrypted_data_.pkl'")
