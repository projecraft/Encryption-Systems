# 📖 Advanced Security & Cryptography Toolkit - User Manual

This file provides a detailed guide on the inputs and outputs for each simulation in the `advanced_security_toolkit.py` script.

---

### 1. Quantum-Resistant Encryption (Simulation)

* **Purpose:** To show how to encrypt and decrypt data using a strong (4096-bit) RSA key.
* **Input:**
    1.  **Choice:** `1` (for text) or `2` (for a file).
    2.  **Data:** If '1', you'll be asked to **enter a text string** (e.g., `kasu`). If '2', you'll be asked to **enter a file path** (e.g., `my_document.txt`).
* **Output:**
    1.  **Ciphertext (Base64):** A long, unreadable string (your encrypted data).
    2.  **Decrypted Data:** Your original text, proving it worked.

---

### 2. Homomorphic Encryption (Simulation)

* **Purpose:** To demonstrate the *idea* of performing calculations (like addition) on "encrypted" (hidden) data.
* **Input:**
    1.  **First number:** (e.g., `25`)
    2.  **Second number:** (e.g., `45`)
* **Output:**
    1.  **Encrypted Sum (Still hidden):** A large number (e.g., `2070`) that is the sum of the *hidden* numbers.
    2.  **Decrypted Sum (Original answer):** The correct sum of your original numbers (e.g., `70`).

---

### 3. Blockchain Key Management (Simulation)

* **Purpose:** To show how blockchain creates a unique, verifiable "fingerprint" (a hash) for a piece of data.
* **Input:**
    1.  **Encryption key:** Any secret string you want to "store" (e.g., `kasu`).
* **Output:**
    1.  **Transaction ID (Hash):** A long SHA-256 hash (e.g., `e265d9...`), representing the unique ID for your key.

---

### 4. Secure Key Generation

* **Purpose:** To generate a strong, highly random key using the system's best random data source.
* **Input:**
    1.  **Length of the key:** A number (e.g., `16`).
* **Output:**
    1.  **Your Secure Randomly Generated Key:** A random string of letters, numbers, and symbols of the length you specified (e.g., `k8Fp2@Q9zR7jL6!B`).

---

### 5. Multi-Factor Authentication (MFA)

* **Purpose:** To simulate the two-step login process (password + one-time code) for better security.
* **Input:**
    1.  **Password:** The correct password is hard-coded as **`mySecret123`**.
    2.  **OTP:** The script will print a random 4-digit OTP (e.g., `4419`). You must **type this exact number** back in.
* **Output:**
    * If correct: `✅ Access Granted: Multi-Factor Authentication Successful!`
    * If incorrect: `❌ Access Denied: Password or OTP Incorrect!`

---

### 6. Lightweight Cryptography (AES)

* **Purpose:** To show a fast, common, and efficient encryption method (AES) used in phones and IoT devices.
* **Input:**
    1.  **Choice:** `1` (for text) or `2` (for a file).
    2.  **Data:** The text or file path you want to encrypt.
* **Output:**
    1.  **Encrypted Data (Base64):** A short, unreadable string.
    2.  **Decrypted Data:** Your original, readable text.
    3.  **Integrity Check:** A message confirming if the data was tampered with.

---

### 7. Honey Encryption (Simulation)

* **Purpose:** To simulate the concept of creating plausible-looking "fake" data to confuse an attacker.
* **Input:**
    1.  **Secret message:** The text you want to hide (e.g., `meet at dawn`).
* **Output:**
    1.  **Honey Encrypted Message:** Your original message with random junk characters added to the end (e.g., `meet at dawnaCZkw8AMa`).

---

### 8. Federated Learning with Privacy

* **Purpose:** To simulate how multiple devices (like phones) can help train an AI model without ever sharing their private data.
* **Input:**
    * **None.** This simulation runs automatically.
* **Output:**
    * **Global Model Result:** A single number (e.g., `5.879...`) that represents the final "learned" value after securely combining the updates from all simulated devices.

---

### 9. Zero-Trust Architecture

* **Purpose:** To demonstrate the "never trust, always verify" security model.
* **Input:**
    1.  **Entity:** A name (e.g., `Device_A`). The script has a pre-approved list (e.g., `Device_A`, `Employee_X`, `Admin_User`).
* **Output:**
    * If the entity is on the list: `✅ VERIFIED: Entity 'Device_A' is verified and trusted!`
    * If not on the list: `❌ DENIED: Entity 'Hacker' is not trusted!`

---

> For installation instructions, please see the main `README.md` file.
>
> **Disclaimer:** These simulations are for educational purposes only and are not secure for real-world use.
