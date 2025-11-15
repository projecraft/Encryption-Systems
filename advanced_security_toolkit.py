# -------------------------------------------------------------------
# FILE: advanced_security_toolkit.py
# -------------------------------------------------------------------
#
# MANUAL & INSTRUCTIONS:
# 1. Save this file as 'advanced_security_toolkit.py'
# 2. In your terminal, run: pip install pycryptodome numpy
# 3. Run this file from your terminal: python advanced_security_toolkit.py
# 4. A menu will appear. Enter a number (0-9) to run a simulation.
#
# -------------------------------------------------------------------

# --- Global Imports ---
import base64
import hashlib
import random
import string
import numpy as np
try:
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP, AES
    from Crypto.Random import get_random_bytes
except ImportError:
    print("Error: Required libraries not found.")
    print("Please run: pip install pycryptodome numpy")
    exit()

# -------------------------------------------------------------------
# 📖 MANUAL 1: Quantum-Resistant Encryption (Simulation)
# -------------------------------------------------------------------
# * Purpose:  To show how to encrypt/decrypt data using a strong (4096-bit) RSA key.
# * Input:
#     1.  A choice: '1' (for text) or '2' (for a file).
#     2.  If '1', the text string you want to encrypt (e.g., kasu).
#     3.  If '2', the file path (e.g., my_document.txt).
# * Output:
#     1.  Ciphertext (Base64 Encoded): A long, unreadable string (the encrypted data).
#     2.  Decrypted Data: The original text, proving the process worked.
# -------------------------------------------------------------------
def run_sim_1_quantum_rsa():
    print("\n--- 🔒 1. Quantum-Resistant Encryption (RSA 4096) ---")
    try:
        choice = input("Select Data Type (1. Text, 2. File Content): ")
        print("Generating 4096-bit RSA key (this may take a moment)...")
        key = RSA.generate(4096)
        public_key = key.publickey()
        cipher = PKCS1_OAEP.new(public_key)

        if choice == '1':
            data = input("Enter the text to encrypt: ").encode()
        elif choice == '2':
            file_path = input("Enter the file path: ")
            with open(file_path, 'rb') as f:
                data = f.read()
        else:
            print("Invalid choice. Defaulting to text.")
            data = input("Enter the text to encrypt: ").encode()

        ciphertext = cipher.encrypt(data)
        print(f"\nCiphertext (Base64):\n{base64.b64encode(ciphertext).decode()}")

        decipher = PKCS1_OAEP.new(key)
        plaintext = decipher.decrypt(ciphertext)
        print(f"\nDecrypted Data:\n{plaintext.decode(errors='ignore')}")

    except FileNotFoundError:
        print(f"Error: File not found at path '{file_path}'")
    except Exception as e:
        print(f"An error occurred: {e}")

# -------------------------------------------------------------------
# 📖 MANUAL 2: Homomorphic Encryption (Simulation)
# -------------------------------------------------------------------
# * Purpose:  To demonstrate the *idea* of performing calculations (like addition)
#             on "encrypted" (hidden) data.
# * Input:
#     1.  First number (e.g., 25)
#     2.  Second number (e.g., 45)
# * Output:
#     1.  Encrypted Sum (Still hidden): A large number (e.g., 2070).
#     2.  Decrypted Sum (Original answer): The correct sum (e.g., 70).
# -------------------------------------------------------------------
def run_sim_2_homomorphic():
    print("\n--- 🔐 2. Homomorphic Encryption (Addition Sim) ---")
    try:
        num1 = int(input("Enter the first number: "))
        num2 = int(input("Enter the second number: "))
        
        offset = 1000  # Secret "key"
        
        enc_num1 = num1 + offset
        enc_num2 = num2 + offset
        print(f"(Simulating... {num1} becomes {enc_num1}, {num2} becomes {enc_num2})")

        enc_sum = enc_num1 + enc_num2
        print(f"\nEncrypted Sum (Still hidden): {enc_sum}")

        dec_sum = enc_sum - (2 * offset)
        print(f"Decrypted Sum (Original answer): {dec_sum}")
        
    except ValueError:
        print("Invalid input. Please enter numbers only.")
    except Exception as e:
        print(f"An error occurred: {e}")

# -------------------------------------------------------------------
# 📖 MANUAL 3: Blockchain Key Management (Simulation)
# -------------------------------------------------------------------
# * Purpose:  To show how blockchain creates a unique, verifiable "fingerprint"
#             (a hash) for a piece of data.
# * Input:
#     1.  Your encryption key: Any secret string (e.g., kasu).
# * Output:
#     1.  Transaction ID: A long SHA-256 hash (the unique "storage" ID).
# -------------------------------------------------------------------
def run_sim_3_blockchain():
    print("\n--- ⛓️ 3. Blockchain Key Management (Hashing) ---")
    try:
        user_key = input("Enter your encryption key (any secret string): ")
        transaction_hash = hashlib.sha256(user_key.encode()).hexdigest()
        
        print("\n🔒 Your key has been 'stored' on the blockchain.")
        print(f"Transaction ID (Hash):\n{transaction_hash}")
        
    except Exception as e:
        print(f"An error occurred: {e}")

# -------------------------------------------------------------------
# 📖 MANUAL 4: AI-Driven Key Generation (Simulation)
# -------------------------------------------------------------------
# * Purpose:  To generate a strong, highly random key using the system's
#             best random data source.
# * Input:
#     1.  Length of the key: A number (e.g., 16).
# * Output:
#     1.  Your Secure Randomly Generated Key: A random string (e.g., 'k8Fp2xQ9zR7jL6mB').
# -------------------------------------------------------------------
def run_sim_4_secure_key_gen():
    print("\n--- 🧠 4. Secure Key Generation ---")
    try:
        key_length = int(input("Enter the length of the key you want: "))
        if key_length <= 0:
            print("Length must be a positive number.")
            return

        charset = string.ascii_letters + string.digits + string.punctuation
        key = ''.join(random.SystemRandom().choice(charset) for _ in range(key_length))
        
        print(f"\n🔐 Your Secure Randomly Generated Key ({key_length} chars):\n{key}")
        
    except ValueError:
        print("Invalid input. Please enter a number.")
    except Exception as e:
        print(f"An error occurred: {e}")

# -------------------------------------------------------------------
# 📖 MANUAL 5: Multi-Factor Authentication (MFA)
# -------------------------------------------------------------------
# * Purpose:  To simulate the two-step login process (password + one-time code).
# * Input:
#     1.  Enter your password: (Correct password is 'mySecret123')
#     2.  Enter the OTP: The script will show you a 4-digit code. Type it back in.
# * Output:
#     * Success: '✅ Access Granted!'
#     * Failure: '❌ Access Denied!'
# -------------------------------------------------------------------
def run_sim_5_mfa():
    print("\n--- 🔑 5. Multi-Factor Authentication (MFA) ---")
    try:
        correct_password = "mySecret123"
        
        user_password = input("Enter your password: ")
        
        otp = random.randint(1000, 9999)
        print(f"\n📨 OTP sent to your registered device: {otp}")
        
        user_otp = int(input("Enter the 4-digit OTP you received: "))

        if user_password == correct_password and user_otp == otp:
            print("\n✅ Access Granted: Multi-Factor Authentication Successful!")
        else:
            print("\n❌ Access Denied: Password or OTP Incorrect!")
            
    except ValueError:
        print("Invalid OTP. Please enter numbers only.")
    except Exception as e:
        print(f"An error occurred: {e}")

# -------------------------------------------------------------------
# 📖 MANUAL 6: Lightweight Cryptography (AES)
# -------------------------------------------------------------------
# * Purpose:  To show a fast, common, and efficient encryption (AES)
#             used in phones, IoT, etc.
# * Input:
#     1.  A choice: '1' (for text) or '2' (for a file).
#     2.  The text or file path.
# * Output:
#     1.  Encrypted Data (Base64 Encoded): A short, unreadable string.
#     2.  Decrypted Data: Your original, readable text.
# -------------------------------------------------------------------
def run_sim_6_lightweight_aes():
    print("\n--- 🌟 6. Lightweight Cryptography (AES) ---")
    try:
        choice = input("Select data type (1. Text, 2. File Content): ")
        key = get_random_bytes(16)  # 128-bit key
        cipher = AES.new(key, AES.MODE_EAX)

        if choice == '1':
            data = input("Enter the text to encrypt: ").encode()
        elif choice == '2':
            file_path = input("Enter the file path: ")
            with open(file_path, 'rb') as f:
                data = f.read()
        else:
            print("Invalid choice. Defaulting to text.")
            data = input("Enter the text to encrypt: ").encode()
        
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(data)

        print(f"\n🔒 Encrypted Data (Base64):\n{base64.b64encode(ciphertext).decode()}")

        cipher_decrypt = AES.new(key, AES.MODE_EAX, nonce=nonce)
        decrypted_data = cipher_decrypt.decrypt(ciphertext)
        
        # Verify integrity
        try:
            cipher_decrypt.verify(tag)
            print(f"\n🔓 Decrypted Data:\n{decrypted_data.decode(errors='ignore')}")
            print("(Integrity Verified: Data was not tampered with)")
        except ValueError:
            print("\n❌ Decryption Failed: Data integrity check failed!")
            
    except FileNotFoundError:
        print(f"Error: File not found at path '{file_path}'")
    except Exception as e:
        print(f"An error occurred: {e}")

# -------------------------------------------------------------------
# 📖 MANUAL 7: Honey Encryption (Simulation)
# -------------------------------------------------------------------
# * Purpose:  To simulate creating "fake" data to confuse an attacker.
# * Input:
#     1.  Secret message: The text you want to hide (e.g., meeting at 9).
# * Output:
#     1.  Honey Encrypted Message: Your message with random junk text added.
# -------------------------------------------------------------------
def run_sim_7_honey_encryption():
    print("\n--- 🍯 7. Honey Encryption (Simulation) ---")
    try:
        secret_message = input("Enter the secret message to encrypt: ")
        
        # In a real system, this is much more complex.
        # Here, we simulate a "honey" (fake) message being appended.
        honey_length = random.randint(10, 20)
        fake_message = ''.join(random.choices(string.ascii_letters + string.digits, k=honey_length))
        
        honey_encrypted_message = secret_message + fake_message
        print(f"\n🔒 Honey Encrypted Message (Fake + Real):\n{honey_encrypted_message}")
        print(f"(Note: An attacker wouldn't know which part is real.)")

    except Exception as e:
        print(f"An error occurred: {e}")

# -------------------------------------------------------------------
# 📖 MANUAL 8: Federated Learning with Privacy (Simulation)
# -------------------------------------------------------------------
# * Purpose:  To simulate how multiple devices can train an AI model
#             without sharing their private data.
# * Input:
#     * None. This simulation runs automatically.
# * Output:
#     * A "Global Model Result" number, representing the combined,
#       secure learning from all simulated devices.
# -------------------------------------------------------------------
def run_sim_8_federated_learning():
    print("\n--- 📈 8. Federated Learning (Privacy Sim) ---")
    try:
        # --- Helper functions for this simulation ---
        def generate_RSA_keypair():
            key = RSA.generate(2048)
            return key, key.publickey()

        def encrypt_update(public_key, data_str):
            cipher = PKCS1_OAEP.new(public_key)
            return cipher.encrypt(data_str.encode())

        def decrypt_update(private_key, enc_data):
            cipher = PKCS1_OAEP.new(private_key)
            return cipher.decrypt(enc_data).decode()
        # --- End of helper functions ---
        
        print("Simulating 3 devices with local data...")
        device_data = [
            np.random.rand(10),  # Device 1 data
            np.random.rand(10),  # Device 2 data
            np.random.rand(10)   # Device 3 data
        ]
        
        private_key, public_key = generate_RSA_keypair()
        print("Generated server keypair...")

        global_model_value = 0
        encrypted_updates = []

        print("Devices are training locally and encrypting updates...")
        for i, data in enumerate(device_data):
            # Simulate local training (just summing data)
            local_model_update = np.sum(data) + np.random.randn() # add noise
            # Encrypt the update before sending
            encrypted_update = encrypt_update(public_key, str(local_model_update))
            encrypted_updates.append(encrypted_update)
            print(f"Device {i+1} sent encrypted update.")

        print("Server received encrypted updates. Decrypting and aggregating...")
        for enc_update in encrypted_updates:
            # Server decrypts with its private key
            decrypted_update_str = decrypt_update(private_key, enc_update)
            global_model_value += float(decrypted_update_str)
            
        final_model = global_model_value / len(device_data)
        print(f"\n🔒 Federated Learning - Global Model Result (Aggregated): {final_model}")

    except Exception as e:
        print(f"An error occurred: {e}")

# -------------------------------------------------------------------
# 📖 MANUAL 9: Zero-Trust Architecture (Simulation)
# -------------------------------------------------------------------
# * Purpose:  To demonstrate the "never trust, always verify" model.
# * Input:
#     1.  Entity trying to access: (e.g., 'Device_A' or 'Hacker')
#         (The system is pre-set to only trust 'Device_A' and 'Employee_X')
# * Output:
#     * 'Entity... is verified and trusted!' (if you type 'Device_A')
#     * 'Entity... is not trusted!' (if you type 'Hacker')
# -------------------------------------------------------------------
def run_sim_9_zero_trust():
    print("\n--- 🛡️ 9. Zero-Trust Architecture ---")
    try:
        # In Zero Trust, no entity is trusted by default.
        # This list represents entities that have *passed* verification.
        trusted_entities = {"Device_A", "Employee_X", "Admin_User"}
        
        print(f"(System only trusts: {trusted_entities})")
        entity = input("Enter the entity trying to access the system: ")

        # Every access request is verified, every time.
        if entity in trusted_entities:
            print(f"\n✅ VERIFIED: Entity '{entity}' is verified and trusted!")
        else:
            print(f"\n❌ DENIED: Entity '{entity}' is not trusted!")
            
    except Exception as e:
        print(f"An error occurred: {e}")

# -------------------------------------------------------------------
# --- Main Menu to Run Simulations ---
# -------------------------------------------------------------------
def main_menu():
    """Displays the main menu and handles user input."""
    
    # A dictionary mapping choices to functions
    simulations = {
        "1": run_sim_1_quantum_rsa,
        "2": run_sim_2_homomorphic,
        "3": run_sim_3_blockchain,
        "4": run_sim_4_secure_key_gen,
        "5": run_sim_5_mfa,
        "6": run_sim_6_lightweight_aes,
        "7": run_sim_7_honey_encryption,
        "8": run_sim_8_federated_learning,
        "9": run_sim_9_zero_trust,
    }
    
    while True:
        print("\n" + "="*40)
        print("      MAIN MENU: SECURITY SIMULATIONS")
        print("="*40)
        print("1. Quantum-Resistant Encryption (RSA)")
        print("2. Homomorphic Encryption (Addition)")
        print("3. Blockchain Key Management (Hashing)")
        print("4. Secure Key Generation")
        print("5. Multi-Factor Authentication (MFA)")
        print("6. Lightweight Cryptography (AES)")
        print("7. Honey Encryption")
        print("8. Federated Learning with Privacy")
        print("9. Zero-Trust Architecture")
        print("0. Exit")
        print("-"*40)
        
        choice = input("Select a simulation to run (0-9): ")
        
        if choice == "0":
            print("Exiting toolkit. Goodbye!")
            break
            
        # Get the function from the dictionary
        selected_function = simulations.get(choice)
        
        if selected_function:
            selected_function() # Run the chosen simulation
        else:
            print("Invalid choice. Please select a number from 0 to 9.")

# This line ensures the menu runs only when the script is executed directly
if __name__ == "__main__":
    print("="*50)
    print("      Welcome to the Advanced Security Toolkit")
    print("      Please ensure you have run:")
    print("      'pip install pycryptodome numpy'")
    print("="*50)
    main_menu()