# Face-Blink
An advanced authentication system merging AI-driven face recognition with salted password hashing. Using encrypted biometrics and strong cryptography, it ensures top-tier security, resists brute-force attacks, and safeguards identities, delivering seamless and unbreakable two-factor protection.

# 🔐 Face-Blink : AI – Secure Two-Factor Authentication with Face Recognition & Salted Password Hashing

## 📌 Overview
**FaceBlink** is an advanced authentication system that combines **bcrypt-salted password hashing** with **AI-powered face recognition** to deliver **unbreakable two-factor security**.  
It uses strong cryptography (AES/Fernet encryption) to protect biometric data, making brute-force attacks and database leaks virtually useless to attackers.

This project ensures that even if an attacker gains access to stored data, they cannot retrieve user passwords or face data in readable form.

---
## Practical video :

https://www.linkedin.com/posts/syed-sameer-74929a315_cybersecurity-ai-facialrecognition-activity-7360324145118633986-c1-r?utm_source=share&utm_medium=member_desktop&rcm=ACoAAE_0SKkBzYKNuy3mRpCwJ4O8rkD1efNr34w

---
## To run the Program :

            1 . First Download the MongoDB Compass GUI - https://www.mongodb.com/try/download/compass
            2 . python ferner key generator.py
            3 . python doit.py

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
**Frontend code used in python - HTML,CSS,JavaScript**

            #####################################
            # HTML Templates
            
            welcome_page = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>Welcome</title>
                <style>
                    body { font-family: Arial, sans-serif; text-align: center; margin-top: 50px; background-color: #f4f4f4; }
                    h1 { color: #333; }
                </style>
            </head>
            <body>
                <h1>Welcome, User {{ uid }}!</h1>
                <p>You have successfully logged in.</p>
            </body>
            </html>
            """
            
            html_code = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
              <meta charset="UTF-8">
              <title>Authentication Page</title>
              <script>
                function openSignupModal() {
                    document.getElementById('signupModal').style.display = 'block';
                }
                function closeSignupModal() {
                    document.getElementById('signupModal').style.display = 'none';
                }
                function openSigninModal() {
                    document.getElementById('signinModal').style.display = 'block';
                }
                function closeSigninModal() {
                    document.getElementById('signinModal').style.display = 'none';
                }
                
                // Close modal if clicking outside of modal content
                window.onclick = function(event) {
                  var signupModal = document.getElementById("signupModal");
                  var signinModal = document.getElementById("signinModal");
                  if (event.target == signupModal) {
                      signupModal.style.display = "none";
                  }
                  if (event.target == signinModal) {
                      signinModal.style.display = "none";
                  }
                }
                
                function validateSignup() {
                    const password = document.getElementById('signupPassword').value;
                    const confirmPassword = document.getElementById('signupConfirmPassword').value;
                    const submitBtn = document.getElementById('signupSubmit');
                    const errorP = document.getElementById('signupError');
                    
                    // Password pattern: 8-16 characters; at least one uppercase, one lowercase, one digit, one special character.
                    const pattern = /^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[!@#$%^&*()_+\\-=\\[\\]{};':"\\\\|,.<>\\/?]).{8,16}$/;
                    
                    if (!pattern.test(password)) {
                        errorP.innerText = "Password must be 8-16 characters long and include uppercase, lowercase, digit, and special character.";
                        submitBtn.disabled = true;
                        return;
                    }
                    
                    if (password !== confirmPassword) {
                        errorP.innerText = "Password and Confirm Password do not match.";
                        submitBtn.disabled = true;
                        return;
                    }
                    
                    errorP.innerText = "";
                    submitBtn.disabled = false;
                }
                
                function validateSignin() {
                    const password = document.getElementById('signinPassword').value;
                    const confirmPassword = document.getElementById('signinConfirmPassword').value;
                    const submitBtn = document.getElementById('signinSubmit');
                    const errorP = document.getElementById('signinError');
                    
                    if (password !== confirmPassword) {
                        errorP.innerText = "Password and Confirm Password do not match.";
                        submitBtn.disabled = true;
                        return;
                    }
                    errorP.innerText = "";
                    submitBtn.disabled = false;
                }
                
                async function submitSignup() {
                    const username = document.getElementById('signupUsername').value;
                    const password = document.getElementById('signupPassword').value;
                    const response = await fetch("/signup_credentials", {
                        method: "POST",
                        headers: {"Content-Type": "application/json"},
                        body: JSON.stringify({username, password})
                    });
                    const data = await response.json();
                    if (data.redirect) {
                        window.location.href = data.redirect;
                    } else {
                        document.getElementById("signupError").innerText = data.message;
                    }
                }
                
                async function submitSignin() {
                    const username = document.getElementById('signinUsername').value;
                    const password = document.getElementById('signinPassword').value;
                    const response = await fetch("/signin_credentials", {
                        method: "POST",
                        headers: {"Content-Type": "application/json"},
                        body: JSON.stringify({username, password})
                    });
                    const data = await response.json();
                    if (data.redirect) {
                        window.location.href = data.redirect;
                    } else {
                        document.getElementById("signinError").innerText = data.message;
                    }
                }
                
                async function signinFacial() {
                    const username = document.getElementById('signinUsername').value;
                    if (!username) {
                        document.getElementById("signinError").innerText = "Please enter your username for facial authentication.";
                        return;
                    }
                    const response = await fetch("/signin_facial", {
                        method: "POST",
                        headers: {"Content-Type": "application/json"},
                        body: JSON.stringify({username})
                    });
                    const data = await response.json();
                    if (data.redirect) {
                        window.location.href = data.redirect;
                    } else {
                        document.getElementById("signinError").innerText = data.message;
                    }
                }
            
                // Password Strength Meter for Signup
                function calculateStrength(pwd) {
                  let score = 0;
                  if (pwd.length >= 8) score++;
                  if (/[a-z]/.test(pwd)) score++;
                  if (/[A-Z]/.test(pwd)) score++;
                  if (/[0-9]/.test(pwd)) score++;
                  if (/[^A-Za-z0-9]/.test(pwd)) score++;
                  return score;
                }
                function updateSignupStrength() {
                  const pwd = document.getElementById('signupPassword').value;
                  const bar = document.getElementById('signupStrengthBar');
                  const text = document.getElementById('signupStrengthText');
            
                  // enforce too-short passwords as Weak
                  if (pwd.length > 0 && pwd.length < 8) {
                    bar.style.width = '20%';
                    bar.style.backgroundColor = '#e74c3c';
                    text.textContent = 'Weak';
                    return;
                  }
            
                  const score = calculateStrength(pwd);
                  const percent = (score / 5) * 100;
                  bar.style.width = percent + '%';
            
                  if (score <= 2) {
                    bar.style.backgroundColor = '#e74c3c';
                    text.textContent = 'Weak';
                  } else if (score === 3) {
                    bar.style.backgroundColor = '#f39c12';
                    text.textContent = 'Medium';
                  } else if (score === 4) {
                    bar.style.backgroundColor = '#27ae60';
                    text.textContent = 'Strong';
                  } else {
                    bar.style.backgroundColor = '#2c3e50';
                    text.textContent = 'Very Strong';
                  }
                }
                document.addEventListener('DOMContentLoaded', () => {
                  document.getElementById('signupPassword')
                          .addEventListener('input', updateSignupStrength);
                });
              </script>
              <style>
                body { font-family: Arial, sans-serif; text-align: center; margin-top: 50px; background-color: #f4f4f4; }
                h1 { color: #333; }
                button { font-size: 16px; padding: 10px 20px; margin: 10px; cursor: pointer; background-color: #007BFF; color: #fff; border: none; border-radius: 5px; transition: background-color 0.3s ease; }
                button:hover { background-color: #0056b3; }
                .modal {
                  display: none;
                  position: fixed;
                  z-index: 1;
                  left: 0; top: 0;
                  width: 100%; height: 100%;
                  overflow: auto;
                  background-color: rgba(0,0,0,0.5);
                }
                .modal-content {
                  background-color: #fefefe;
                  margin: 10% auto;
                  padding: 20px;
                  border: 1px solid #888;
                  width: 300px;
                  border-radius: 5px;
                }
                #signupStrengthMeter {
                  width: 100%;
                  height: 8px;
                  background: #e0e0e0;
                  border-radius: 4px;
                  margin: 8px 0;
                }
                #signupStrengthBar {
                  height: 100%;
                  width: 0;
                  border-radius: 4px;
                  transition: width 0.3s ease;
                }
                #signupStrengthText {
                  margin: 4px 0 0;
                  font-size: 0.9em;
                }
              </style>
            </head>
            <body>
              <h1>Welcome to Our Website</h1>
              <p>Please choose an option:</p>
              <button onclick="openSigninModal()">Sign In</button>
              <button onclick="openSignupModal()">Sign Up</button>
              <p id="output"></p>
              
              <!-- Signup Modal -->
              <div id="signupModal" class="modal">
                <div class="modal-content">
                  <h2>Sign Up</h2>
                  <p>It will capture your face first after entering your username and password.<br>The password will be taken once only.</p>
                  <label>Username:</label><br/>
                  <input type="text" id="signupUsername" oninput="validateSignup()" required><br/><br/>
                  <label>Password:</label><br/>
                  <input type="text" id="signupPassword" oninput="validateSignup()" required><br/>
                  
                  <!-- strength meter inserted -->
                  <div id="signupStrengthMeter">
                    <div id="signupStrengthBar"></div>
                  </div>
                  <p id="signupStrengthText"></p><br/>
                  
                  <label>Confirm Password:</label><br/>
                  <input type="text" id="signupConfirmPassword" oninput="validateSignup()" required><br/><br/>
                  <button id="signupSubmit" onclick="submitSignup()" disabled>Submit</button>
                  <button onclick="closeSignupModal()">Cancel</button>
                  <p id="signupError" style="color:red;"></p>
                </div>
              </div>
              
              <!-- Signin Modal -->
              <div id="signinModal" class="modal">
                <div class="modal-content">
                  <h2>Sign In</h2>
                  <label>Username:</label><br/>
                  <input type="text" id="signinUsername" oninput="validateSignin()" required><br/><br/>
                  <label>Password:</label><br/>
                  <input type="text" id="signinPassword" oninput="validateSignin()" required><br/><br/>
                  <label>Confirm Password:</label><br/>
                  <input type="text" id="signinConfirmPassword" oninput="validateSignin()" required><br/><br/>
                  <button id="signinSubmit" onclick="submitSignin()" disabled>Submit</button>
                  <button onclick="signinFacial()">Facial Authentication</button>
                  <button onclick="closeSigninModal()">Cancel</button>
                  <p id="signinError" style="color:red;"></p>
                </div>
              </div>
              
            </body>
            </html>
            """

------------------------------

**DataBase used in python - MongoDB** 

         client = MongoClient("mongodb://localhost:27017/")
         db = client["CanISeeYouInHeaven"]

---------------------------------------

**Backend used in python - Flask**

                        #####################################
                        # Flask Routes
                        
                        @app.route('/')
                        def home():
                            return render_template_string(html_code)
                        
                        @app.route('/signup_credentials', methods=['POST'])
                        def signup_credentials():
                            data = request.get_json()
                            username = data.get("username")
                            password = data.get("password")
                            
                            if not username or not password:
                                return jsonify({"message": "Username and password are required."}), 400
                        
                            # enforce JS policy server-side
                            strength = get_password_strength(password)
                            if strength == 'Weak':
                                return jsonify({
                                    "message": "Password too weak. It must be at least 8 characters and include uppercase, lowercase, digits, and special symbols."
                                }), 400
                        
                            pattern = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};\'":\\|,.<>\/?]).{8,16}$'
                            if not re.match(pattern, password):
                                return jsonify({"message": "Password must be 8-16 characters long and include uppercase, lowercase, digit, and special character."})
                        
                            result = process_signup(username, password)
                            if isinstance(result, str) and "Registration successful" in result:
                                return jsonify({"redirect": url_for('welcome', uid=username)})
                            else:
                                return jsonify({"message": result})
                        
                        @app.route('/signin_credentials', methods=['POST'])
                        def signin_credentials():
                            data = request.get_json()
                            username = data.get("username")
                            password = data.get("password")
                            
                            if not username or not password:
                                return jsonify({"message": "Username and password are required."}), 400
                            
                            user_doc = db.users.find_one({"uid": username})
                            if not user_doc:
                                return jsonify({"message": "Username does not exist."})
                            
                            if "password_hash" not in user_doc:
                                return jsonify({"message": "No password set for this user. Try facial authentication."}), 400
                        
                            if not check_password(password, user_doc["password_hash"]):
                                return jsonify({"message": "Password is incorrect."}), 401
                            
                            return jsonify({"redirect": url_for('welcome', uid=username)})
                        
                        @app.route('/signin_facial', methods=['POST'])
                        def signin_facial():
                            data = request.get_json()
                            username = data.get("username")
                            if not username:
                                return jsonify({"message": "Username required for facial authentication."}), 400
                            result = run_signin_logic(username)
                            if isinstance(result, str) and "Login successful" in result:
                                return jsonify({"redirect": url_for('welcome', uid=username)})
                            else:
                                return jsonify({"message": result})
                        
                        @app.route('/welcome')
                        def welcome():
                            uid = request.args.get("uid")
                            if not uid:
                                return "Invalid Access"
                            else:
                                return render_template_string(welcome_page, uid=uid)

---------------------------------------

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

**While In Signup :**

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
