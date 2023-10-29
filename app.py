from flask import Flask, render_template, request, redirect, url_for, jsonify, g, make_response
from google.cloud import storage, firestore
from werkzeug.utils import secure_filename
from datetime import timedelta
import os
import jwt

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)

storage_client = storage.Client()

JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
BUCKET_NAME = os.environ.get("BUCKET_NAME")

bucket = storage_client.get_bucket(BUCKET_NAME)

db = firestore.Client()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def check_jwt():
    jwt_cookie = request.cookies.get('jwt')
    print("jwt -", jwt_cookie)

    if jwt_cookie:
        try:
            decoded = jwt.decode(jwt_cookie, JWT_SECRET_KEY, algorithms=[
                'HS256'])

            email = decoded.get('email')
            if email:
                g.email = email
                return True
        except:
            return False

    return False


@app.before_request
def protect():
    if request.endpoint=="static":
        return
    if check_jwt():
        if request.endpoint == "login" or request.endpoint == "signup":
            return redirect("/")
    elif request.endpoint != "login" and request.endpoint != "signup":
        return redirect(url_for('login'))
    
def get_user(email):
    query = db.collection('user').where('email', '==', email).limit(1)
    
    results = query.stream()

    for user_document in results:
        return user_document.to_dict()

    return None


def add_user(email, password):
    userExists = get_user(email)
    if userExists:
        return False
    
    db.collection("user").add({
        'email': email,
        'password': password,
    })

    return True

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = get_user(email)
        if user:
            return jsonify({"status":"Fail", "message":'Email already exists!'}), 409
        else:
            add_user(email, password)
            return jsonify({"status":"Success"}), 201
    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = get_user(email)

        print(user)

        if user and user['password'] == password:
            token = jwt.encode(
                {'email': email}, JWT_SECRET_KEY, algorithm='HS256')

            response = make_response(jsonify({"status":"Success"}), 201)
            response.set_cookie("jwt", token, httponly=True)
            return response
        response = make_response(jsonify({"status":"Fail", "message":"Invalid email or password"}), 400)
        return response

    return render_template('login.html')


@app.route("/logout", methods=["POST"])
def logout():
    response = make_response(redirect(url_for("login")))
    response.set_cookie('jwt', '', expires=0)
    return response


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' in request.files:
            file = request.files['file']
            print(file)
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)

                # Upload the file to Google Cloud Storage
                blob = bucket.blob(filename)
                blob.upload_from_file(file)

                # Store metadata in Firestore
                file_metadata = {
                    'creator':g.get("email"),
                    'filename': filename,
                    'location': f'https://storage.googleapis.com/{BUCKET_NAME}/{filename}',
                }
                db.collection('files').add(file_metadata)

    # Retrieve metadata from Firestore
    file_metadata = db.collection('files').where("creator","==", g.get("email")).stream()
    data = [{'name':img.to_dict()["filename"], 'url':img.to_dict()["location"]} for img in file_metadata]

    return render_template('index.html', images=data)

@app.route('/download/<filename>')
def download_file(filename):
    # Generate a signed URL for the download link
    blob = bucket.blob(filename)
    signed_url = blob.generate_signed_url(
        version='v4',
        expiration=timedelta(minutes=30),  # Adjust the expiration time as needed
        method='GET'
    )
    return redirect(signed_url)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
