import cv2
import numpy as np
import hashlib
from cryptography.fernet import Fernet

# Generate a Fernet key
def generate_key():
    return Fernet.generate_key()

# Encrypt message using Fernet key
def encrypt_message(message, key):
    fernet = Fernet(key)
    return fernet.encrypt(message.encode())

# Decrypt message using Fernet key
def decrypt_message(encrypted_message, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message).decode()

# Hash password using SHA-256
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Embed a message into an image using LSB steganography
def embed_message(img, msg, password):
    key = generate_key()  # Generate encryption key
    encrypted_msg = encrypt_message(msg, key)  # Encrypt the message
    hashed_password = hash_password(password).encode()  # Hash the password

    # Combine password hash, encryption key, and encrypted message
    final_data = hashed_password + b'|' + key + b'|' + encrypted_msg

    # Ensure message fits inside image
    if len(final_data) * 8 > img.size:
        raise ValueError("Message too large for the image provided.")

    binary_data = np.unpackbits(np.frombuffer(final_data, dtype=np.uint8))
    flat_img = img.flatten()

    # Embed the binary data into the LSBs of the image
    flat_img[:len(binary_data)] = (flat_img[:len(binary_data)] & 0xFE) | binary_data

    # Reshape and save the modified image
    img = flat_img.reshape(img.shape)
    output_filename = f"advanced_encrypted_image_{np.random.randint(1000, 9999)}.png"
    cv2.imwrite(output_filename, img)
    print(f"Message embedded with encryption and saved as '{output_filename}'")

# Extract the hidden message from an image
def extract_message(img, password):
    flat_img = img.flatten()
    binary_data = flat_img & 1  # Extract LSBs
    all_bytes = np.packbits(binary_data).tobytes()  # Convert binary back to bytes

    try:
        # Debugging: Print the first few bytes to check format
        print("Extracted raw data:", all_bytes[:100])  

        if b'|' not in all_bytes:
            raise ValueError("No embedded data found or incorrect format.")

        # Split data into hashed password, key, and encrypted message
        parts = all_bytes.split(b'|', 2)
        if len(parts) != 3:
            raise ValueError("Extracted data is corrupted or incomplete.")
        
        hashed_password, key, encrypted_msg = parts

        # Debugging: Print extracted components
        print("Extracted Hashed Password:", hashed_password)
        print("Extracted Key Length:", len(key))
        print("Extracted Encrypted Message:", encrypted_msg[:50])

        # Verify password
        if hash_password(password).encode() != hashed_password:
            print("YOU ARE NOT AUTHORIZED")
            return

        # Validate extracted key
        if len(key) != 44:  # Fernet keys are exactly 44 bytes (Base64 encoded)
            raise ValueError("Invalid encryption key extracted.")

        # Decrypt the message
        decrypted_msg = decrypt_message(encrypted_msg, key)

        # Save decrypted message to file
        output_file = f"decrypted_message_{np.random.randint(1000, 9999)}.txt"
        with open(output_file, "w") as file:
            file.write(decrypted_msg)
        print(f"Decrypted message saved as '{output_file}'")

    except Exception as e:
        print("Error in decryption:", str(e))

# Main function to run the steganography tool
def main():
    print("--- Advanced Steganography Project for Marcos Commando ---")
    img_path = input("Enter the path of the image: ")
    img = cv2.imread(img_path)

    if img is None:
        print("Invalid image path.")
        return

    choice = input("Do you want to (1) Encode or (2) Decode a message? (1/2): ").strip()

    if choice == '1':
        msg = input("Enter the secret message: ")
        password = input("Enter a passcode: ")
        embed_message(img, msg, password)

    elif choice == '2':
        password = input("Enter the passcode used during embedding: ")
        extract_message(img, password)
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
