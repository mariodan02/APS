from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import uuid
import os
import json
import hashlib

from models import db, User, Credential, RevocationRecord, BlockchainBlock, OCSPResponse
from crypto_utils import generate_keypair, sign_data, verify_signature, hash_data, selective_disclosure
from blockchain import SimpleBlockchain
from ocsp_service import ocsp

app = Flask(__name__)
app.config['SECRET_KEY'] = 'development-key-change-this-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///erasmus_credentials.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Register blueprints
app.register_blueprint(ocsp)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Initialize database and create sample data
@app.before_first_request
def create_tables():
    db.create_all()
    
    # Check if we already have sample data
    if User.query.count() == 0:
        create_sample_data()

def create_sample_data():
    """Create sample data for the application"""
    
    # Create CA user
    ca_private, ca_public = generate_keypair()
    ca = User(
        username="ca_admin",
        password=generate_password_hash("ca_password"),
        role="ca",
        public_key=ca_public,
        private_key=ca_private,
        university_did="did:web:ca.edu",
        university_name="Certificate Authority",
        university_country="EU"
    )
    db.session.add(ca)
    
    # Create issuer university (Rennes)
    rennes_private, rennes_public = generate_keypair()
    rennes = User(
        username="rennes_admin",
        password=generate_password_hash("rennes_password"),
        role="issuer",
        public_key=rennes_public,
        private_key=rennes_private,
        university_did="did:web:rennes.fr",
        university_name="Université de Rennes",
        university_country="France"
    )
    db.session.add(rennes)
    
    # Create verifier university (Salerno)
    salerno_private, salerno_public = generate_keypair()
    salerno = User(
        username="salerno_admin",
        password=generate_password_hash("salerno_password"),
        role="verifier",
        public_key=salerno_public,
        private_key=salerno_private,
        university_did="did:web:unisa.it",
        university_name="Università di Salerno",
        university_country="Italy"
    )
    db.session.add(salerno)
    
    # Create 3 sample students
    for i in range(1, 4):
        student_private, student_public = generate_keypair()
        student_real_id = f"S{i}12345"
        student_hash_id = hashlib.md5(student_real_id.encode()).hexdigest()
        
        student = User(
            username=f"student{i}",
            password=generate_password_hash(f"student{i}_password"),
            role="student",
            public_key=student_public,
            private_key=student_private,
            student_pseudonym=f"student_{hashlib.md5(f'student{i}'.encode()).hexdigest()[:8]}",
            student_hash_id=student_hash_id
        )
        db.session.add(student)
    
    db.session.commit()
    
    # Initialize blockchain
    blockchain = SimpleBlockchain()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            
            # Redirect based on role
            if user.role == 'issuer':
                return redirect(url_for('issuer_dashboard'))
            elif user.role == 'student':
                return redirect(url_for('student_dashboard'))
            elif user.role == 'verifier':
                return redirect(url_for('verifier_dashboard'))
            elif user.role == 'ca':
                return redirect(url_for('ca_dashboard'))
        else:
            flash('Invalid username or password.')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Issuer University Routes
@app.route('/issuer')
@login_required
def issuer_dashboard():
    if current_user.role != 'issuer':
        flash('Unauthorized access.')
        return redirect(url_for('index'))
    
    students = User.query.filter_by(role='student').all()
    credentials = Credential.query.filter_by(issuer_id=current_user.id).all()
    
    return render_template('issuer.html', 
                          students=students, 
                          credentials=credentials)

@app.route('/issuer/issue_credential', methods=['POST'])
@login_required
def issue_credential():
    if current_user.role != 'issuer':
        return jsonify({"error": "Unauthorized"}), 403
    
    data = request.json
    student_id = data.get('student_id')
    course_code = data.get('course_code')
    course_isced = data.get('course_isced')
    exam_grade = data.get('exam_grade')
    exam_date_str = data.get('exam_date')
    ects_credits = data.get('ects_credits')
    
    # Validation
    if not all([student_id, course_code, exam_grade, exam_date_str, ects_credits]):
        return jsonify({"error": "Missing required fields"}), 400
    
    # Parse exam date
    try:
        exam_date = datetime.strptime(exam_date_str, '%Y-%m-%d')
    except ValueError:
        return jsonify({"error": "Invalid date format"}), 400
    
    # Create credential
    credential = Credential(
        issuer_id=current_user.id,
        student_id=student_id,
        course_code=course_code,
        course_isced_code=course_isced or "0613",  # Default ISCED code for Computer Science
        exam_grade=exam_grade,
        exam_passed=True if int(exam_grade.split('/')[0]) >= 18 else False,  # Pass if grade >= 18/30
        exam_date=exam_date,
        ects_credits=int(ects_credits),
        expiration_date=datetime.utcnow() + timedelta(days=365*5),  # Valid for 5 years
        revocation_id=str(uuid.uuid4())
    )
    
    # Sign the credential
    credential_dict = {
        "uuid": credential.uuid,
        "issuer_id": credential.issuer_id,
        "student_id": credential.student_id,
        "course_code": credential.course_code,
        "exam_grade": credential.exam_grade,
        "exam_date": credential.exam_date.isoformat(),
        "ects_credits": credential.ects_credits
    }
    credential.signature = sign_data(current_user.private_key, credential_dict)
    
    # Save to database
    db.session.add(credential)
    db.session.commit()
    
    # Add to blockchain
    blockchain = SimpleBlockchain()
    credential.blockchain_reference = blockchain.add_credential(credential)
    db.session.commit()
    
    return jsonify({
        "success": True,
        "credential_uuid": credential.uuid,
        "message": "Credential issued successfully"
    })

@app.route('/issuer/revoke_credential', methods=['POST'])
@login_required
def revoke_credential():
    if current_user.role != 'issuer':
        return jsonify({"error": "Unauthorized"}), 403
    
    data = request.json
    credential_uuid = data.get('credential_uuid')
    reason = data.get('reason')
    
    if not credential_uuid or not reason:
        return jsonify({"error": "Missing required fields"}), 400
    
    # Get credential
    credential = Credential.query.filter_by(uuid=credential_uuid, issuer_id=current_user.id).first()
    if not credential:
        return jsonify({"error": "Credential not found"}), 404
    
    # Create revocation record
    revocation = RevocationRecord(
        credential_uuid=credential_uuid,
        reason=reason,
        revoker_id=current_user.id
    )
    
    # Add to blockchain
    blockchain = SimpleBlockchain()
    revocation.transaction_hash = blockchain.revoke_credential(credential_uuid, reason, current_user.id)
    
    # Update credential status
    credential.status = "revoked"
    
    db.session.add(revocation)
    db.session.commit()
    
    return jsonify({
        "success": True,
        "message": "Credential revoked successfully"
    })

# Student Routes
@app.route('/student')
@login_required
def student_dashboard():
    if current_user.role != 'student':
        flash('Unauthorized access.')
        return redirect(url_for('index'))
    
    credentials = Credential.query.filter_by(student_id=current_user.id).all()
    verifiers = User.query.filter_by(role='verifier').all()
    
    return render_template('student.html', 
                          credentials=credentials,
                          verifiers=verifiers)

@app.route('/student/view_credential/<uuid>')
@login_required
def view_credential(uuid):
    if current_user.role != 'student':
        return jsonify({"error": "Unauthorized"}), 403
    
    credential = Credential.query.filter_by(uuid=uuid, student_id=current_user.id).first()
    if not credential:
        return jsonify({"error": "Credential not found"}), 404
    
    return jsonify(credential.to_dict())

@app.route('/student/share_credential', methods=['POST'])
@login_required
def share_credential():
    if current_user.role != 'student':
        return jsonify({"error": "Unauthorized"}), 403
    
    data = request.json
    credential_uuid = data.get('credential_uuid')
    verifier_id = data.get('verifier_id')
    fields_to_disclose = data.get('fields_to_disclose', [])
    
    if not credential_uuid or not verifier_id:
        return jsonify({"error": "Missing required fields"}), 400
    
    # Get credential
    credential = Credential.query.filter_by(uuid=credential_uuid, student_id=current_user.id).first()
    if not credential:
        return jsonify({"error": "Credential not found"}), 404
    
    # Check if credential is revoked
    blockchain = SimpleBlockchain()
    status = blockchain.verify_credential(credential_uuid)
    if status == "revoked":
        return jsonify({
            "error": "Cannot share revoked credential",
            "status": status
        }), 400
    
    # Create selective disclosure
    disclosed_data = selective_disclosure(credential, fields_to_disclose)
    
    # In a real app, this would be sent to the verifier
    # Here we just simulate by creating a session variable
    session['shared_credential'] = {
        "disclosed_data": disclosed_data,
        "verifier_id": verifier_id,
        "shared_by": current_user.id,
        "shared_at": datetime.utcnow().isoformat()
    }
    
    return jsonify({
        "success": True,
        "message": "Credential shared successfully",
        "disclosed_data": disclosed_data
    })

# Verifier University Routes
@app.route('/verifier')
@login_required
def verifier_dashboard():
    if current_user.role != 'verifier':
        flash('Unauthorized access.')
        return redirect(url_for('index'))
    
    # Get shared credential from session (this is a simulation)
    shared_credential = session.get('shared_credential')
    
    return render_template('verifier.html', 
                          shared_credential=shared_credential)

@app.route('/verifier/verify_credential', methods=['POST'])
@login_required
def verify_credential():
    if current_user.role != 'verifier':
        return jsonify({"error": "Unauthorized"}), 403
    
    data = request.json
    credential_uuid = data.get('credential_uuid')
    
    if not credential_uuid:
        return jsonify({"error": "Missing credential_uuid"}), 400
    
    # Check blockchain for credential status
    blockchain = SimpleBlockchain()
    status = blockchain.verify_credential(credential_uuid)
    
    # Get OCSP response
    ocsp_response = {
        "credential_uuid": credential_uuid
    }
    
    response = app.test_client().post(
        '/api/ocsp/check',
        json=ocsp_response,
        content_type='application/json'
    )
    
    ocsp_result = json.loads(response.data)
    
    # Combine results
    result = {
        "blockchain_status": status,
        "ocsp_status": ocsp_result['responses'][0]['certStatus'],
        "verified_at": datetime.utcnow().isoformat() + "Z",
        "valid": status == "good" and ocsp_result['responses'][0]['certStatus'] == "good"
    }
    
    return jsonify(result)

# Certificate Authority Routes
@app.route('/ca')
@login_required
def ca_dashboard():
    if current_user.role != 'ca':
        flash('Unauthorized access.')
        return redirect(url_for('index'))
    
    # Get blockchain status
    blockchain = SimpleBlockchain()
    is_valid = blockchain.is_valid()
    
    blocks = BlockchainBlock.query.order_by(BlockchainBlock.id.desc()).limit(10).all()
    revocations = RevocationRecord.query.order_by(RevocationRecord.revocation_timestamp.desc()).all()
    
    return render_template('ca.html', 
                          blockchain_valid=is_valid,
                          blocks=blocks,
                          revocations=revocations)

@app.route('/ca/blockchain_status')
@login_required
def blockchain_status():
    if current_user.role != 'ca':
        return jsonify({"error": "Unauthorized"}), 403
    
    blockchain = SimpleBlockchain()
    is_valid = blockchain.is_valid()
    
    blocks = BlockchainBlock.query.order_by(BlockchainBlock.id.desc()).all()
    block_data = []
    
    for block in blocks:
        block_data.append({
            "id": block.id,
            "hash": block.hash,
            "previous_hash": block.previous_hash,
            "timestamp": block.timestamp.isoformat(),
            "data": json.loads(block.data) if block.data else None,
            "nonce": block.nonce
        })
    
    return jsonify({
        "blockchain_valid": is_valid,
        "blocks": block_data
    })

if __name__ == '__main__':
    app.run(debug=True)