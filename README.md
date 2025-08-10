# Face-Blink
Full-Stack Program based on advanced authentication system merging AI-driven face recognition with salted password hashing. Using encrypted biometrics and strong cryptography, it ensures top-tier security, resists brute-force attacks, and safeguards identities, delivering seamless and unbreakable two-factor protection.

# 🔐 Face-Blink : AI – Secure Two-Factor Authentication with Face Recognition & Salted Password Hashing

## 📌 Overview
**FaceBlink** is an advanced authentication system that combines **bcrypt-salted password hashing** with **AI-powered face recognition** to deliver **unbreakable two-factor security**.  
It uses strong cryptography (AES/Fernet encryption) to protect biometric data, making brute-force attacks and database leaks virtually useless to attackers.

This project ensures that even if an attacker gains access to stored data, they cannot retrieve user passwords or face data in readable form.

---

## 🚀 Key Features
- **Two-Factor Authentication (2FA)**: Password + Face Recognition
- **Bcrypt Salted Hashing** for password storage (one-way, non-reversible)
- **AES/Fernet Encryption** for face encoding & image storage
- **Real-Time Face Recognition** using `face_recognition` & OpenCV
- **Brute-force Resistant** with adjustable bcrypt rounds
- **Cross-platform Web App** built using Flask
- **Seamless User Flow** with instant feedback

---

## 📂 Tech Stack
- **Frontend:** HTML, CSS, JavaScript
- **Backend:** Python (Flask)
- **AI/ML:** `face_recognition` (dlib), NumPy
- **Security:** bcrypt, cryptography (Fernet AES)
- **Database:** MongoDB / File-based storage
- **Libraries:** OpenCV, SciPy

---

## 🔄 Authentication Flow
1. **User Registration**
   - User enters a **username** and **password**
   - Password is **hashed with bcrypt** (salt added automatically)
   - Face is captured (image or live camera)
   - Face encoding (numerical data) is generated
   - Encoding is **encrypted with AES/Fernet** and stored
   - User is successfully registered

2. **User Login**
   - User enters username and password
   - Password is verified using bcrypt’s `checkpw`
   - If correct, camera captures face
   - Live face encoding is generated & compared with decrypted stored encoding
   - Access is granted only if **both factors match**

---

## 🛡 Security Design
- **Password Security**: One-way salted hashing prevents password retrieval.
- **Biometric Security**: Stored face encodings are encrypted; raw images are never exposed.
- **Brute-force Resistance**: High bcrypt rounds increase attack difficulty.
- **Replay Attack Protection**: Encodings are generated per login session.

---

## 📸 BlinkLock (Optional Feature)
To prevent spoofing with photos/videos, a **Blink Detection** mechanism can be added, requiring the user to blink before authentication is approved.

---

## 📊 Flow Diagram
**Password Flow Diagram :**

  [User Enters Password]
            |
            v
  [Generate Salt (bcrypt.gensalt)]
            |
            v
  [Hash Password with bcrypt]
            |
            v
  [Store Hashed Password in Database]
            |
            v
  [When Logging In]
            |
            v
  [User Enters Password Again]
            |
            v
  [Retrieve Stored Hash from DB]
            |
            v
  [bcrypt.checkpw(Input, Stored Hash)]
            |
     Yes ---+--- No
     |            |
     v            v
  [Password OK]  [Reject Login]


**Face login Flow Diagram :**


[User Provides Live Face or Image]
          |
          v
[Capture Image via Camera]
          |
          v
[Extract Face Encoding (Numerical Representation)]
          |
          v
[Encrypt Encoding using Fernet]
          |
          v
[Store Encrypted Encoding in Database]
          |
          v
[When Authenticating]
          |
          v
[Capture New Face Image]
          |
          v
[Extract Face Encoding]
          |
          v
[Decrypt Stored Encoding]
          |
          v
[Compare New Encoding with Stored Encoding]
          |
   Match ---+--- No Match
   |               |
   v               v
[Face OK]      [Reject Login]



**Blink Pattern Flow Diagram :**

**While In Signup**

[User Signup Starts]
       |
       v
[Live Camera Feed Starts]
       |
       v
[Detect Face & Eye Landmarks]
       |
       v
[User Performs Blink Pattern]
       |
       v
[EAR Analysis Confirms Pattern]
       |
       v
[Store Blink Pattern Data (Encrypted) in Database]
       |
       v
[Proceed to Face Encoding]
       |
       v
[Encrypt & Store Face Encoding in Database]
       |
       v
[Hash & Store Password in Database]
       |
       v
[Signup Successful]


**In Signin :**

[User Signin Starts]
       |
       v
[Live Camera Feed Starts]
       |
       v
[Detect Face & Eye Landmarks]
       |
       v
[User Performs Blink Pattern]
       |
       v
[EAR Analysis Confirms Pattern]
       |
       v
[Retrieve & Decrypt Stored Blink Pattern from Database]
       |
       v
[Compare Live Pattern with Stored Pattern]
       |
   Match? -------- No ---> [Authentication Failed]
       |
      Yes
       |
       v
[Proceed to Face Encoding Verification]
       |
       v
[Retrieve Stored Face Encoding from Database]
       |
       v
[Compare Live Encoding with Stored Encoding]
       |
   Match? -------- No ---> [Authentication Failed]
       |
      Yes
       |
       v
[Password Check (Hashed)]
       |
   Match? -------- No ---> [Authentication Failed]
       |
      Yes
       |
       v
[Authentication Successful]
