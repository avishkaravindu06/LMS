import smtplib
import random
import os
from flask import Flask, render_template, request, session, redirect, url_for, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
import firebase_admin
from firebase_admin import credentials, auth, firestore

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "fallback-secret-key-123")

# Rate Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# Firebase Setup
def initialize_firebase():
    try:
        # Private key එකේ \n නිවැරදිව හඳුනා ගැනීමට
        private_key = os.getenv("FIREBASE_PRIVATE_KEY")
        if private_key:
            private_key = private_key.replace("\\n", "\n")

        firebase_config_dict = {
            "type": "service_account",
            "project_id": os.getenv("FIREBASE_PROJECT_ID"),
            "private_key_id": os.getenv("FIREBASE_PRIVATE_KEY_ID"),
            "private_key": private_key,
            "client_email": os.getenv("FIREBASE_CLIENT_EMAIL"),
            "token_uri": "https://oauth2.googleapis.com/token",
        }
        
        if not firebase_admin._apps:
            cred = credentials.Certificate(firebase_config_dict)
            firebase_admin.initialize_app(cred)
        return firestore.client()
    except Exception as e:
        print(f"CRITICAL: Firebase Init Error: {e}")
        return None

db = initialize_firebase()

# --- Email Logic ---
def send_email(receiver_email, subject, body):
    sender_email = os.getenv("GMAIL_USER")
    app_password = os.getenv("GMAIL_PASS")
    if not sender_email or not app_password:
        print("Email credentials not set!")
        return False
        
    message = f"Subject: {subject}\n\nDear Student,\n\n{body}\n\nBest Regards,\nEduPro Team"
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, app_password)
        server.sendmail(sender_email, receiver_email, message)
        server.quit()
        return True
    except Exception as e:
        print(f"Mail Error: {e}")
        return False

# Validation
def is_valid_mobile(mobile): return mobile.isdigit() and len(mobile) == 10
def is_valid_address(address): return len(address.strip().split()) >= 1 # සරල ලිපින සඳහා

@app.route('/')
def home():
    if 'user_id' in session: return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/set-session', methods=['POST'])
def set_session():
    data = request.json
    id_token = data.get('idToken')
    try:
        decoded_token = auth.verify_id_token(id_token)
        uid = decoded_token['uid']
        session['user_id'] = uid
        
        if db:
            user_doc = db.collection('students').document(uid).get()
            if user_doc.exists:
                return jsonify({"status": "success", "new_user": False})
        
        session['temp_google'] = {
            "uid": uid, 
            "name": decoded_token.get('name', 'Student'), 
            "email": decoded_token.get('email')
        }
        return jsonify({"status": "success", "new_user": True})
    except Exception as e:
        print(f"Session Error: {e}")
        return jsonify({"status": "error"}), 401

@app.route('/register', methods=['POST'])
def register():
    name = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')
    mobile = request.form.get('mobile')
    address = request.form.get('address')

    if not is_valid_mobile(mobile): return "Invalid Mobile Number!"
    
    otp = str(random.randint(100000, 999999))
    session['temp_user'] = {
        "name": name, "email": email, "password": password, 
        "mobile": mobile, "address": address, "otp": otp
    }
    
    if send_email(email, "Verification Code", f"Your OTP is: {otp}"):
        return render_template('verify_otp.html', email=email)
    return "Failed to send OTP. Please check Gmail settings."

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    otp = "".join([request.form.get(f'otp{i}') for i in range(1, 7)])
    temp = session.get('temp_user')
    
    if temp and otp == temp['otp']:
        try:
            user = auth.create_user(email=temp['email'], password=temp['password'], display_name=temp['name'])
            if db:
                db.collection('students').document(user.uid).set({
                    "name": temp['name'], "email": temp['email'], "mobile": temp['mobile'],
                    "address": temp['address'], "id_no": "STU-" + user.uid[:5].upper(),
                    "initial": temp['name'][0].upper()
                })
            session['user_id'] = user.uid
            session.pop('temp_user', None)
            return jsonify({"status": "success"})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)})
    return jsonify({"status": "error", "message": "Invalid OTP"})

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: return redirect(url_for('home'))
    if not db: return "Database connection error."
    
    user = db.collection('students').document(session['user_id']).get()
    return render_template('index.html', student=user.to_dict()) if user.exists else redirect(url_for('logout'))

@app.route('/complete-profile')
def complete_profile_route(): return render_template('complete_profile.html')

@app.route('/save-google-profile', methods=['POST'])
def save_google_profile():
    temp = session.get('temp_google')
    mobile = request.form.get('mobile')
    address = request.form.get('address')
    
    if temp and is_valid_mobile(mobile) and db:
        db.collection('students').document(temp['uid']).set({
            "name": temp['name'], "email": temp['email'], "mobile": mobile,
            "address": address, "id_no": "STU-" + temp['uid'][:5].upper(),
            "initial": temp['name'][0].upper()
        })
        session['user_id'] = temp['uid']
        session.pop('temp_google', None)
        return redirect(url_for('dashboard'))
    return redirect(url_for('home'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)