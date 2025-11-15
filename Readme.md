# Advanced Security & Cryptography Simulations

This project is a collection of simple, command-line simulations for various advanced security and cryptography concepts. It's designed for educational purposes to help visualize and understand how these technologies work in a simplified way.

The toolkit is contained in a single Python script (`advanced_security_toolkit.py`) and features an interactive menu to run each simulation.

## 🚀 Features

* Quantum-Resistant Encryption (RSA 4096-bit Simulation)
* Homomorphic Encryption (Simple Addition Simulation)
* Blockchain Key Management (Hashing Simulation)
* Secure Key Generation
* Multi-Factor Authentication (MFA) Simulation
* Lightweight Cryptography (AES Simulation)
* Honey Encryption (Simulation)
* Federated Learning with Privacy (Simulation)
* Zero-Trust Architecture (Simulation)

## 🔧 Requirements

* Python 3.x
* `pycryptodome`
* `numpy`

## ⚙️ Installation

1.  Clone this repository or download the `advanced_security_toolkit.py` file.
2.  Open your terminal or command prompt.
3.  Install the required packages using pip:

    ```bash
    pip install pycryptodome numpy
    ```

## ▶️ How to Run

1.  Navigate to the directory containing the script in your terminal.
2.  Run the script using Python:

    ```bash
    python advanced_security_toolkit.py
    ```

3.  This will launch an interactive menu. Simply enter the number of the simulation you wish to run (1-9) or '0' to exit.

    ```
    ========================================
          MAIN MENU: SECURITY SIMULATIONS
    ========================================
    1. Quantum-Resistant Encryption (RSA)
    2. Homomorphic Encryption (Addition)
    3. Blockchain Key Management (Hashing)
    4. Secure Key Generation
    5. Multi-Factor Authentication (MFA)
    6. Lightweight Cryptography (AES)
    7. Honey Encryption
    8. Federated Learning with Privacy
    9. Zero-Trust Architecture
    0. Exit
    ----------------------------------------
    Select a simulation to run (0-9):
    ```

## Simulations Explained

| # | Simulation | Description |
| :--- | :--- | :--- |
| **1** | **Quantum-Resistant (RSA)** | Encrypts/decrypts data using a very large 4096-bit RSA key. |
| **2** | **Homomorphic (Addition)** | Simulates performing addition on "encrypted" (hidden) numbers. |
| **3** | **Blockchain (Hashing)** | Creates a unique SHA-256 hash (like a Transaction ID) for a secret key. |
| **4** | **Secure Key Generation** | Generates a strong, random key of a user-specified length. |
| **5** | **Multi-Factor Auth (MFA)** | Simulates a 2-step login with a password and a one-time-password (OTP). |
| **6** | **Lightweight Crypto (AES)** | Encrypts/decrypts data using the fast and efficient AES algorithm. |
| **7** | **Honey Encryption** | Simulates how fake "honey" data can be added to a secret to confuse attackers. |
| **8** | **Federated Learning** | Simulates how multiple devices can securely contribute to training an AI model. |
| **9** | **Zero-Trust Architecture** | Simulates the "never trust, always verify" security model. |

---

## ⚠️ Disclaimer

**This project is for educational and demonstrative purposes ONLY.**

The simulations provided are highly simplified and **ARE NOT secure for real-world use.** Do not use this code to protect sensitive, production data. Real-world cryptography is significantly more complex and should be implemented by experts using vetted libraries.

## 📄 License

This project is licensed under the MIT License.