# CipherDrop-Confidential-Document-Sharing-through-Multi-Layered-Encryption

## 📄 Abstract

In today’s era of rampant data exchange, safeguarding sensitive file transfers is essential. CipherDrop is a web-based file-sharing platform built with **Flask**, designed to securely transfer documents such as PDFs and images between authenticated users. It employs **multi-layered symmetric encryption (Fernet, AES, Triple DES)** and ensures decryption keys are shared separately via email. This **dual-channel security model** significantly strengthens confidentiality and privacy for academic, professional, and enterprise communications.

---

## 🔐 Key Features

- **Multi-Algorithm Encryption:** Choose from Fernet, AES, or Triple DES for securing files.
- **Dual-Channel Delivery:** Files stored on the server; decryption keys sent via email.
- **User Authentication:** Secure registration, login, and session management.
- **File Upload & Decryption:** Upload encrypted files and decrypt them via the interface.
- **Email-Based Key Dispatch:** Keys are transmitted using secure SMTP with TLS.
- **Max File Size Supported:** 10MB

---

## 🛠️ System Modules

| Module               | Description                                                       |
|----------------------|-------------------------------------------------------------------|
| User Authentication  | Handles registration, login, and session management.              |
| File Upload          | Accepts, validates, and processes uploaded files.                 |
| Encryption Engine    | Implements Fernet, AES, and Triple DES encryption schemes.        |
| Email Key Dispatch   | Sends decryption keys via email using SMTP.                       |
| Decryption Interface | Allows users to decrypt received files by entering keys.          |

---

## 🧪 Functional Testing

| Feature              | Status                                                              |
|----------------------|---------------------------------------------------------------------|
| User Authentication  | ✅ Successful login and registration                                 |
| File Encryption      | ✅ Files correctly encrypted/decrypted with all 3 algorithms         |
| Key Delivery         | ✅ Keys successfully received by intended users                      |
| File Integrity       | ✅ No corruption observed                                             |
| File Size Limit      | ✅ System restricts files > 10MB                                     |

---

## ⏱️ Performance Evaluation

| Algorithm | 1MB File | 5MB File | 10MB File |
|-----------|----------|----------|-----------|
| Fernet    | 0.15s    | 0.62s    | 1.2s      |
| AES-256   | 0.18s    | 0.75s    | 1.5s      |
| 3DES      | 0.25s    | 1.15s    | 2.3s      |

---

## 🧠 Architecture Overview

- Flask Web App with secure user authentication
- Encrypted file storage on the server
- SMTP integration for key distribution
- Decryption module with input validation and error handling
- Dual-channel system for maximum confidentiality

---

## 📈 Results Summary

- End-to-end secure transmission validated
- Seamless key-based decryption using received keys
- User interface tested for usability and reliability
- Functional under real-world scenarios involving file sharing up to 10MB

---

## ✅ Conclusion

CipherDrop delivers a robust solution for secure document exchange by:
- Integrating **multi-layered symmetric encryption**
- Ensuring **key isolation through email delivery**
- Maintaining **high usability through Flask interfaces**

This platform is ideal for use in environments demanding **data confidentiality**, such as:
- Academic institutions
- Legal and enterprise communications
- Personal secure document handling

---

**Authors:**  
Mekala Varun  
N. V. S. Sanjana  
Department of Computer Science and Engineering,  
Amrita School of Computing, Bengaluru, Amrita Vishwa Vidyapeetham, India  
Emails: bl.en.u4aie22037@bl.students.amrita.edu, bl.en.u4aie22041@bl.students.amrita.edu

---

