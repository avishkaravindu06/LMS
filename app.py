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
# සටහන: Render වල Environment Variables විදිහට මේවා ඇතුළත් කරන්න ඕනේ.
# දැනට මම ඔබ එවූ Key එක මේ විදිහටම තැබුවා, නමුත් මෙය .env එකට දැමීම වඩා සුදුසුයි.
firebase_config_dict = {
  "type": "service_account",
  "project_id": os.getenv("FIREBASE_PROJECT_ID", "online-class-43b28"),
  "private_key_id": os.getenv("FIREBASE_PRIVATE_KEY_ID", "b2049810737fae075f40f95a03ce2892d2fe2813"),
  "private_key": os.getenv("FIREBASE_PRIVATE_KEY", "").replace("\\n", "\n"),
  "client_email": os.getenv("FIREBASE_CLIENT_EMAIL", "firebase-adminsdk-fbsvc@online-class-43b28.iam.gserviceaccount.com"),
  "client_id": "101083172211467753948",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40online-class-43b28.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
}

if not firebase_admin._apps:
    try:
        cred = credentials.Certificate(firebase_config_dict)
        firebase_admin.initialize_app(cred)
    except Exception as e:
        print(f"Firebase Init Error: {e}")

db = firestore.client()

# --- Email Logic ---
def send_email(receiver_email, subject, body):
    sender_email = os.getenv("GMAIL_USER")
    app_password = os.getenv("GMAIL_PASS")
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
def is_valid_address(address): return len(address.strip().split()) >= 2

# Routes (ඔබේ Code එක එලෙසම පවතී)
@app.route('/')
def home():
    if 'user_id' in session: return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/info')
def info(): return render_template('info.html')

@app.route('/help')
def help_page(): return render_template('help.html')

@app.route('/set-session', methods=['POST'])
@limiter.limit("10 per minute")
def set_session():
    data = request.json
    id_token = data.get('idToken')
    try:
        decoded_token = auth.verify_id_token(id_token)
        uid = decoded_token['uid']
        session['user_id'] = uid
        user_doc = db.collection('students').document(uid).get()
        if user_doc.exists:
            return jsonify({"status": "success", "new_user": False})
        session['temp_google'] = {"uid": uid, "name": decoded_token.get('name', 'Student'), "email": decoded_token.get('email')}
        return jsonify({"status": "success", "new_user": True})
    except: return jsonify({"status": "error"}), 401

@app.route('/complete-profile')
def complete_profile_route(): return render_template('complete_profile.html')

@app.route('/save-google-profile', methods=['POST'])
def save_google_profile():
    temp = session.get('temp_google')
    mobile, address = request.form.get('mobile'), request.form.get('address')
    if temp and is_valid_mobile(mobile) and is_valid_address(address):
        db.collection('students').document(temp['uid']).set({
            "name": temp['name'], "email": temp['email'], "mobile": mobile,
            "address": address, "id_no": "STU-" + temp['uid'][:5].upper(),
            "initial": temp['name'][0].upper()
        })
        session['user_id'] = temp['uid']
        session.pop('temp_google', None)
        return redirect(url_for('dashboard'))
    return redirect(url_for('home'))

@app.route('/register', methods=['POST'])
@limiter.limit("3 per minute")
def register():
    name, email, password = request.form.get('name'), request.form.get('email'), request.form.get('password')
    mobile, address = request.form.get('mobile'), request.form.get('address')
    if not is_valid_mobile(mobile) or not is_valid_address(address): return "Invalid Input!"
    otp = str(random.randint(100000, 999999))
    session['temp_user'] = {"name": name, "email": email, "password": password, "mobile": mobile, "address": address, "otp": otp}
    if send_email(email, "Verification Code", f"Your code is: {otp}"): return render_template('verify_otp.html', email=email)
    return "Email Failed."

@app.route('/verify-otp', methods=['POST'])
@limiter.limit("5 per minute")
def verify_otp():
    otp = "".join([request.form.get(f'otp{i}') for i in range(1, 7)])
    temp = session.get('temp_user')
    if temp and otp == temp['otp']:
        try:
            user = auth.create_user(email=temp['email'], password=temp['password'], display_name=temp['name'])
            db.collection('students').document(user.uid).set({
                "name": temp['name'], "email": temp['email'], "mobile": temp['mobile'],
                "address": temp['address'], "id_no": "STU-" + user.uid[:5].upper(),
                "initial": temp['name'][0].upper()
            })
            session['user_id'] = user.uid
            session.pop('temp_user', None)
            return jsonify({"status": "success"})
        except Exception as e: return jsonify({"status": "error", "message": str(e)})
    return jsonify({"status": "error", "message": "Invalid OTP"})

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: return redirect(url_for('home'))
    user = db.collection('students').document(session['user_id']).get()
    return render_template('index.html', student=user.to_dict()) if user.exists else redirect(url_for('logout'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"status": "error", "message": "Too many requests! Please wait a moment."}), 429

if __name__ == '__main__':
    # Local වලදී පමණක් මෙය වැඩ කරයි
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)