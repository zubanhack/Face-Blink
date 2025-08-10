from flask import Flask, render_template_string, jsonify, request, redirect, url_for, Response
import cv2
import face_recognition
import os
import numpy as np
import time
from scipy.spatial import distance as dist
from cryptography.fernet import Fernet
from pymongo import MongoClient
from bson.binary import Binary
import re
import bcrypt

def load_fernet_key(path: str = "fernet.key") -> bytes:
    """
    Read a Fernet key from the given file path.
    Raises FileNotFoundError if the file is missing.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Fernet key file not found: {path}")
    with open(path, "rb") as key_file:
        return key_file.read()

key_path = os.getenv("FERNET_KEY_PATH", "fernet.key")
FERNET_KEY = load_fernet_key(path=key_path)
fernet = Fernet(FERNET_KEY)

app = Flask(__name__)

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["CanISeeYouInHeaven"]

#####################################
# Server-side password strength checker

def get_password_strength(password: str) -> str:
    """
    Returns one of: 'Weak', 'Medium', 'Strong', 'Very Strong'
    based on length and character-class criteria.
    """
    score = 0
    if len(password) >= 8:
        score += 1
    if re.search(r'[a-z]', password):
        score += 1
    if re.search(r'[A-Z]', password):
        score += 1
    if re.search(r'\d', password):
        score += 1
    if re.search(r'[^A-Za-z0-9]', password):
        score += 1

    if score <= 2:
        return 'Weak'
    elif score == 4:
        return 'Medium'
    elif score == 6:
        return 'Strong'
    else:
        return 'Very Strong'
        
#####################################
# 🔧 ADD: bcrypt-based password helpers (non-reversible)

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode(), salt).decode()

def check_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


#####################################
# 🔧 ADD: face encoding / image encryption helpers

def encrypt_face_encoding(encoding_bytes: bytes) -> bytes:
    return fernet.encrypt(encoding_bytes)

def decrypt_face_encoding(token: bytes) -> bytes:
    return fernet.decrypt(token)

def secure_store_face_image(image_bytes: bytes) -> bytes:
    return fernet.encrypt(image_bytes)


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

#####################################
# Existing functions for face capture and login logic (unchanged)
def run_login_logic(uid):
    
    def calculate_ear(eye):
        A = dist.euclidean(eye[1], eye[5])
        B = dist.euclidean(eye[2], eye[4])
        C = dist.euclidean(eye[0], eye[3])
        return (A + B) / (2.0 * C) if C != 0 else 0

    def capture_face_and_blink(user_id):
        if db.users.find_one({"uid": user_id}):
            print(f"User '{user_id}' is already registered.")
            return f"User '{user_id}' is already registered."

        cam = cv2.VideoCapture(0)
        if not cam.isOpened():
            print("Error: Camera not accessible.")
            return "Error: Camera not accessible."

        EAR_THRESHOLD = 0.2
        BLINK_GOAL   = 3
        captured_face_image = None
        face_encoding_saved = None
        blink_pattern = []
        start_time = time.time()
        frame_count = 0
        state = {"ears": [], "closed": False, "blinks": 0}

        while time.time() - start_time < 30:
            ret, frame = cam.read()
            if not ret:
                print("Failed to capture image.")
                break
            frame_count += 1
            display_frame = frame.copy()
            rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            try:
                face_locations = face_recognition.face_locations(rgb_frame) or []
            except Exception as e:
                print("Error during face detection:", e)
                face_locations = []

            if face_locations:
                top, right, bottom, left = face_locations[0]
                captured_face_image = frame[top:bottom, left:right].copy()
                cv2.rectangle(display_frame, (left, top), (right, bottom), (0, 255, 0), 2)

                landmarks_list = face_recognition.face_landmarks(rgb_frame, face_locations)
                if landmarks_list:
                    landmarks = landmarks_list[0]
                    left_eye = landmarks.get('left_eye', [])
                    right_eye = landmarks.get('right_eye', [])
                    if left_eye and right_eye:
                        avg_ear = (calculate_ear(left_eye) + calculate_ear(right_eye)) / 2.0
                        blink_pattern.append(1 if avg_ear < EAR_THRESHOLD else 0)

                        # blink detection and count update
                        if avg_ear < EAR_THRESHOLD:
                            if not state["closed"]:
                                state["closed"] = True
                        else:
                            if state["closed"]:
                                state["blinks"] += 1
                                state["closed"] = False

                        # display blink count on the interface
                        cv2.putText(
                            display_frame,
                            f"{state['blinks']}/{BLINK_GOAL}",
                            (left, top - 10),
                            cv2.FONT_HERSHEY_SIMPLEX,
                            0.9,
                            (0, 0, 255),
                            2
                        )

                        # break if blink goal reached
                        if state["blinks"] >= BLINK_GOAL:
                            print(f"Blink goal reached: {state['blinks']}/{BLINK_GOAL}")
                            break

                face_encodings = face_recognition.face_encodings(rgb_frame, face_locations)
                if face_encodings:
                    face_encoding_saved = face_encodings[0]

            cv2.imshow("Register - Face Capture", display_frame)
            if cv2.waitKey(1) & 0xFF == ord('q'):
                print("Exit command received. Finalizing data...")
                break

        cam.release()
        cv2.destroyAllWindows()

        # require minimum blinks for registration
        if state["blinks"] < BLINK_GOAL:
            print(f"Registration failed: Only {state['blinks']} blinks detected. Minimum {BLINK_GOAL} required.")
            return f"Registration failed: Only {state['blinks']} blinks detected. Minimum {BLINK_GOAL} required."

        if captured_face_image is not None and face_encoding_saved is not None:
            ret, buffer = cv2.imencode('.jpg', captured_face_image)
            img_bytes = buffer.tobytes()
            encrypted_img = secure_store_face_image(img_bytes)

            # encoding bytes
            enc_bytes = face_encoding_saved.tobytes()
            encrypted_encoding = encrypt_face_encoding(enc_bytes)

            # Blink pattern as bytes
            blink_bytes = bytes([1] * state["blinks"] + [0] * (BLINK_GOAL - state["blinks"]))
            enc_blink = secure_store_face_image(blink_bytes)

            user_data = {
                "uid": user_id,
                "face_image": Binary(encrypted_img),
                "encrypted_face_encoding": Binary(encrypted_encoding),
                "blink_pattern": Binary(enc_blink),
                "timestamp": time.time()
            }
            db.users.insert_one(user_data)
            return f"Registration successful for user: {user_id}"
        else:
            return "Failed to capture face data."
    
    return capture_face_and_blink(uid)

def run_signin_logic(uid):
    
    def calculate_ear(eye):
        A = dist.euclidean(eye[1], eye[5])
        B = dist.euclidean(eye[2], eye[4])
        C = dist.euclidean(eye[0], eye[3])
        return (A + B) / (2.0 * C) if C != 0 else 0

    def login_face(user_id):
        user_doc = db.users.find_one({"uid": user_id})
        if not user_doc:
            return f"User '{user_id}' is not registered."

        # 🔧 ADD: decrypt stored face encoding with env-var key
        stored_bytes = decrypt_face_encoding(user_doc["encrypted_face_encoding"])
        stored_face_encoding = np.frombuffer(stored_bytes, dtype=np.float64)
        
        cam = cv2.VideoCapture(0)
        if not cam.isOpened():
            return "Error: Camera not accessible."
        
        EAR_THRESHOLD = 0.2
        TOLERANCE = 0.45
        TIMEOUT = 30
        start_time = time.time()
        
        face_matched = False
        blink_count = 0
        required_blink_count = 3
        blink_in_progress = False
        live_face_encoding = None
        
        while time.time() - start_time < TIMEOUT:
            ret, frame = cam.read()
            if not ret:
                continue
            
            display_frame = frame.copy()
            rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            face_locations = face_recognition.face_locations(rgb_frame) or []
            
            if (face_locations):
                if len(face_locations) > 1:
                    largest_face = max(face_locations,
                                       key=lambda rect: (rect[2] - rect[0]) * (rect[1] - rect[3]))
                    face_locations = [largest_face]
                (top, right, bottom, left) = face_locations[0]
                cv2.rectangle(display_frame, (left, top), (right, bottom), (0, 255, 0), 2)
                face_encodings = face_recognition.face_encodings(rgb_frame, face_locations)
                if face_encodings:
                    if live_face_encoding is None:
                        live_face_encoding = face_encodings[0]
                    distance = face_recognition.face_distance([stored_face_encoding], live_face_encoding)[0]
                    if distance < TOLERANCE:
                        face_matched = True
                        cv2.putText(display_frame, "Face Matched", (50, 30),
                                    cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)
                        try:
                            landmarks_list = face_recognition.face_landmarks(rgb_frame, face_locations)
                        except Exception as e:
                            print("Face landmark detection error:", e)
                            landmarks_list = None
                        if landmarks_list:
                            landmarks = landmarks_list[0]
                            left_eye = landmarks.get('left_eye', [])
                            right_eye = landmarks.get('right_eye', [])
                            if left_eye and right_eye:
                                left_ear = calculate_ear(left_eye)
                                right_ear = calculate_ear(right_eye)
                                avg_ear = (left_ear + right_ear) / 2.0
                                if avg_ear < EAR_THRESHOLD:
                                    blink_in_progress = True
                                    cv2.putText(display_frame, "Eyes Closed", (50, 70),
                                                cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 255), 2)
                                else:
                                    if blink_in_progress:
                                        blink_count += 1
                                        blink_in_progress = False
                                        cv2.putText(display_frame, "Blink Detected!", (50, 70),
                                                    cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)
                                        
                                        if blink_count >= required_blink_count:
                                            cam.release()
                                            cv2.destroyAllWindows()
                                            return f"Login successful for user {user_id}"
                                            
                    else:
                        cv2.putText(display_frame, "Face Not Matched", (50, 30),
                                    cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 255), 2)
                        cam.release()
                        cv2.destroyAllWindows()
                        return "Face does not match!"
            else:
                cv2.putText(display_frame, "No face detected", (50, 30),
                            cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 255), 2)

            # ── ADDED: persistent face‐match status overlay ──
            if face_matched:
                cv2.putText(display_frame, "Face Matched", (50, 30),
                            cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)
            elif face_locations:
                cv2.putText(display_frame, "Face Not Matched", (50, 30),
                            cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 255), 2)

            # ── ADDED: blink counter display ──
            cv2.putText(display_frame,
                        f"{blink_count}/{required_blink_count}",
                        (50, 110),
                        cv2.FONT_HERSHEY_SIMPLEX,
                        1,
                        (255, 255, 0),
                        2)

            cv2.imshow("Login - Live Camera Feed", display_frame)
            if cv2.waitKey(1) & 0xFF == ord('q'):
                break
        
        cam.release()
        cv2.destroyAllWindows()

        if not face_matched:
            return "Face does not match!"
        if blink_count < required_blink_count:
            return "No blink detected. Login failed."

        if "blink_pattern" in user_doc:
            stored_blink_value = int(np.sum(user_doc["blink_pattern"]))
            if blink_count >= stored_blink_value:
                return f"Login successful for user {user_id}"
            else:
                return f"Blink pattern does not match (live: {blink_count}, expected: {stored_blink_value}). Login failed."
        else:
            return f"Login successful for user {user_id}"

    return login_face(uid)

#####################################
# New wrapper function for signup to include password storage with encryption
def process_signup(uid, password):
    result = run_login_logic(uid)
    if "Registration successful" in result:
        hashed = hash_password(password)
        db.users.update_one(
            {"uid": uid},
            {"$set": {"password_hash": hashed}}
        )
    return result

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

if __name__ == "__main__":
    app.run(debug=True)