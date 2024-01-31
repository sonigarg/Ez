from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import os
import secrets

app = Flask(_name_)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = 'secret_key' 
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_ops_user = db.Column(db.Boolean, default=False)
    files = db.relationship('File', backref='author', lazy=True)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@app.route('/ops-login', methods=['POST'])
def ops_login():
    data = request.get_json()

    username = data.get('username')
    password = data.get('password')

    if username not in User or User[username]['password'] != password:
        return jsonify({'message': 'Invalid credentials'}), 401

    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token)


@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

@app.route('/ops-upload', methods=['POST'])

def upload_file():
    if 'file' not in request.files:
        return jsonify({'message': 'No file part'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'message': 'No selected file'}), 400
    
    if file and allowed_file(file.filename):
        file.save(os.path.join('uploads', file.filename))
        return jsonify({'message': 'File successfully uploaded'}), 200

    return jsonify({'message': 'Invalid file type. Allowed types: pptx, docx, xlsx'}), 400

def ops_upload():
    upload_file()
    if request.method == 'POST':
        ops_user = User.query.filter_by(id=1).first() 
        if ops_user and ops_user.is_ops_user:
            file = request.files['file']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                new_file = File(filename=filename, user_id=ops_user.id)
                db.session.add(new_file)
                db.session.commit()
                return jsonify({'message': 'File uploaded successfully'})
            else:
                return jsonify({'error': 'Invalid file type'})
        else:
            return jsonify({'error': 'Ops User not authorized'})

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'pptx', 'docx', 'xlsx'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/client-signup', methods=['POST'])
def client_signup():
    data = request.get_json()

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    if username in clients:
        return jsonify({'message': 'Username already exists'}), 409

    hashed_password = generate_password_hash(password, method='sha256')

    clients[username] = {'password': hashed_password}

    encrypted_url = urllib.parse.quote(f'/activate/{username}')

    return jsonify({'message': 'User successfully registered', 'activation_url': encrypted_url}), 201

@app.route('/client-email-verify', methods=['POST'])
def send_verification_email(email, verification_token):
    subject = 'Account Verification'
    body = f'Thank you for signing up! Please click the following link to verify your email: ' \
           f'http://localhost:5000/verify/{username}/{verification_token}'  # Replace with your actual server URL

    msg = Message(subject, recipients=[email], body=body)
    mail.send(msg)

def client_email_verify():
    data = request.get_json()

    username = data.get('username')
    email = data.get('email')

    if not username or not email:
        return jsonify({'message': 'Username and email are required'}), 400

    if username not in clients:
        return jsonify({'message': 'User not found'}), 404

    verification_token = secrets.token_urlsafe(32)

    verification_tokens[username] = verification_token

    send_verification_email(email, verification_token)

    return jsonify({'message': 'Verification email sent successfully'}), 200


@app.route('/client-login', methods=['POST'])
def client_login():
    data = request.get_json()

    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    if username not in clients:
        return jsonify({'message': 'User not found'}), 404

    stored_password_hash = clients[username]['password']
    if not check_password_hash(stored_password_hash, password):
        return jsonify({'message': 'Invalid credentials'}), 401

    return jsonify({'message': 'Login successful'}), 200


@app.route('/download-file/<int:file_id>', methods=['GET'])
def download_file(file_id):
    client_user = User.query.filter_by(id=2).first()
    file = File.query.get_or_404(file_id)
    if client_user and file.user_id == client_user.id:
        download_link = generate_download_link(file.filename)
        return jsonify({'download-link': download_link, 'message': 'success'})
    else:
        return jsonify({'error': 'Unauthorized access'})

@app.route('/list-files', methods=['GET'])
def list_files():
    client_user = User.query.filter_by(id=2).first() 
    if client_user:
        files = File.query.filter_by(user_id=client_user.id).all()
        file_list = [file.filename for file in files]
        return jsonify({'files': file_list})
    else:
        return jsonify({'error': 'Unauthorized access'})


if _name_ == '_main_':
    app.run(debug=True)