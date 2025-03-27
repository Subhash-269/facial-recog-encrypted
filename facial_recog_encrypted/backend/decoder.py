# decoder.py
import time
import base64
import pickle
from phe.paillier import EncryptedNumber

def decrypt_and_decode_image(encrypted_chunks, private_key, output_image_path):
    start_time = time.time()
    # (existing implementation that writes to disk)
    t0 = time.time()
    decrypted_b64_parts = []
    for enc_val in encrypted_chunks:
        decrypted_int = private_key.decrypt(enc_val)
        byte_length = (decrypted_int.bit_length() + 7) // 8
        chunk_bytes = decrypted_int.to_bytes(byte_length, byteorder='big')
        chunk_str = chunk_bytes.decode('utf-8')
        decrypted_b64_parts.append(chunk_str)
    t1 = time.time()
    print(f"[decoder] Decrypting {len(encrypted_chunks)} chunks took {t1 - t0:.4f} seconds.")

    t0 = time.time()
    complete_b64_string = "".join(decrypted_b64_parts)
    t1 = time.time()
    print(f"[decoder] Concatenating Base64 string took {t1 - t0:.4f} seconds.")

    t0 = time.time()
    img_data = base64.b64decode(complete_b64_string)
    t1 = time.time()
    print(f"[decoder] Base64 decoding to bytes took {t1 - t0:.4f} seconds.")
    
    t0 = time.time()
    with open(output_image_path, "wb") as f:
        f.write(img_data)
    t1 = time.time()
    print(f"[decoder] Writing image to disk took {t1 - t0:.4f} seconds.")

    total_time = time.time() - start_time
    print(f"[decoder] Total decryption & decode time: {total_time:.4f} seconds.")

def decrypt_and_decode_image_data(encrypted_chunks, private_key):
    """
    Decrypts a list of encrypted chunk dictionaries (each with keys "ciphertext" and "exponent")
    using the provided private key, reassembles the Base64 string, and returns the decoded image bytes.
    """
    decrypted_b64_parts = []
    for enc_chunk in encrypted_chunks:
        # Reconstruct an EncryptedNumber from its JSON representation.
        ciphertext = int(enc_chunk["ciphertext"])
        exponent = enc_chunk["exponent"]
        encrypted_number = EncryptedNumber(private_key.public_key, ciphertext, exponent)
        decrypted_int = private_key.decrypt(encrypted_number)
        byte_length = (decrypted_int.bit_length() + 7) // 8
        chunk_bytes = decrypted_int.to_bytes(byte_length, byteorder='big')
        chunk_str = chunk_bytes.decode('utf-8')
        decrypted_b64_parts.append(chunk_str)
    complete_b64_string = "".join(decrypted_b64_parts)
    image_bytes = base64.b64decode(complete_b64_string)
    return image_bytes

if __name__ == "__main__":
    # Example usage: load from pickle and decrypt to a file
    pkl_file = "encrypted_data_.pkl"
    restored_image_path = "restored_image.png"
    
    with open(pkl_file, "rb") as f:
        data = pickle.load(f)
    
    pub_key = data["public_key"]
    pri_key = data["private_key"]
    ciphertexts = data["ciphertexts"]
    
    decrypt_and_decode_image(ciphertexts, pri_key, restored_image_path)
    print(f"[decoder] Decrypted image saved as '{restored_image_path}'.")
