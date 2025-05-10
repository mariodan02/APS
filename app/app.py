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

# Inizializzazione delle estensioni
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Registrazione dei blueprint
app.register_blueprint(ocsp)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_sample_data():
    """Crea dati di esempio per l'applicazione"""
    
    # Crea utente CA
    ca_private, ca_public = generate_keypair()
    ca = User(
        username="ca_admin",
        password=generate_password_hash("ca_password"),
        role="ca",
        public_key=ca_public,
        private_key=ca_private,
        university_did="did:web:ca.edu",
        university_name="Autorità di Certificazione",
        university_country="UE"
    )
    db.session.add(ca)
    
    # Crea università emittente (Rennes)
    rennes_private, rennes_public = generate_keypair()
    rennes = User(
        username="rennes_admin",
        password=generate_password_hash("rennes_password"),
        role="issuer",
        public_key=rennes_public,
        private_key=rennes_private,
        university_did="did:web:rennes.fr",
        university_name="Université de Rennes",
        university_country="Francia"
    )
    db.session.add(rennes)
    
    # Crea università verificatrice (Salerno)
    salerno_private, salerno_public = generate_keypair()
    salerno = User(
        username="salerno_admin",
        password=generate_password_hash("salerno_password"),
        role="verifier",
        public_key=salerno_public,
        private_key=salerno_private,
        university_did="did:web:unisa.it",
        university_name="Università di Salerno",
        university_country="Italia"
    )
    db.session.add(salerno)
    
    # Crea 3 studenti di esempio
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
    
    # Inizializza blockchain
    blockchain = SimpleBlockchain()

# Inizializza database e crea dati di esempio
with app.app_context():
    db.create_all()
    # Controlla se abbiamo già dei dati di esempio
    if User.query.count() == 0:
        create_sample_data()

# Route
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
            
            # Reindirizza in base al ruolo
            if user.role == 'issuer':
                return redirect(url_for('issuer_dashboard'))
            elif user.role == 'student':
                return redirect(url_for('student_dashboard'))
            elif user.role == 'verifier':
                return redirect(url_for('verifier_dashboard'))
            elif user.role == 'ca':
                return redirect(url_for('ca_dashboard'))
        else:
            flash('Nome utente o password non validi.')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Route Università Emittente
@app.route('/issuer')
@login_required
def issuer_dashboard():
    if current_user.role != 'issuer':
        flash('Accesso non autorizzato.')
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
        return jsonify({"error": "Non autorizzato"}), 403
    
    data = request.json
    student_id = data.get('student_id')
    course_code = data.get('course_code')
    course_isced = data.get('course_isced')
    exam_grade = data.get('exam_grade')
    exam_date_str = data.get('exam_date')
    ects_credits = data.get('ects_credits')
    
    # Validazione
    if not all([student_id, course_code, exam_grade, exam_date_str, ects_credits]):
        return jsonify({"error": "Campi obbligatori mancanti"}), 400
    
    # Analizza data dell'esame
    try:
        exam_date = datetime.strptime(exam_date_str, '%Y-%m-%d')
    except ValueError:
        return jsonify({"error": "Formato data non valido"}), 400
    
    # Crea credenziale
    credential = Credential(
        issuer_id=current_user.id,
        student_id=student_id,
        course_code=course_code,
        course_isced_code=course_isced or "0613",  # Codice ISCED predefinito per Informatica
        exam_grade=exam_grade,
        exam_passed=True if int(exam_grade.split('/')[0]) >= 18 else False,  # Passa se voto >= 18/30
        exam_date=exam_date,
        ects_credits=int(ects_credits),
        expiration_date=datetime.utcnow() + timedelta(days=365*5),  # Valido per 5 anni
        revocation_id=str(uuid.uuid4())
    )
    
    # Firma la credenziale
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
    
    # Salva nel database
    db.session.add(credential)
    db.session.commit()
    
    # Aggiungi alla blockchain
    blockchain = SimpleBlockchain()
    credential.blockchain_reference = blockchain.add_credential(credential)
    db.session.commit()
    
    return jsonify({
        "success": True,
        "credential_uuid": credential.uuid,
        "message": "Credenziale emessa con successo"
    })

@app.route('/issuer/revoke_credential', methods=['POST'])
@login_required
def revoke_credential():
    if current_user.role != 'issuer':
        return jsonify({"error": "Non autorizzato"}), 403
    
    data = request.json
    credential_uuid = data.get('credential_uuid')
    reason = data.get('reason')
    
    if not credential_uuid or not reason:
        return jsonify({"error": "Campi obbligatori mancanti"}), 400
    
    # Ottieni credenziale
    credential = Credential.query.filter_by(uuid=credential_uuid, issuer_id=current_user.id).first()
    if not credential:
        return jsonify({"error": "Credenziale non trovata"}), 404
    
    # Crea record di revoca
    revocation = RevocationRecord(
        credential_uuid=credential_uuid,
        reason=reason,
        revoker_id=current_user.id
    )
    
    # Aggiungi alla blockchain
    blockchain = SimpleBlockchain()
    revocation.transaction_hash = blockchain.revoke_credential(credential_uuid, reason, current_user.id)
    
    # Aggiorna stato della credenziale
    credential.status = "revoked"
    
    db.session.add(revocation)
    db.session.commit()
    
    return jsonify({
        "success": True,
        "message": "Credenziale revocata con successo"
    })

# Route Studente
@app.route('/student')
@login_required
def student_dashboard():
    if current_user.role != 'student':
        flash('Accesso non autorizzato.')
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
        return jsonify({"error": "Non autorizzato"}), 403
    
    credential = Credential.query.filter_by(uuid=uuid, student_id=current_user.id).first()
    if not credential:
        return jsonify({"error": "Credenziale non trovata"}), 404
    
    return jsonify(credential.to_dict())

@app.route('/student/share_credential', methods=['POST'])
@login_required
def share_credential():
    if current_user.role != 'student':
        return jsonify({"error": "Non autorizzato"}), 403
    
    data = request.json
    credential_uuid = data.get('credential_uuid')
    verifier_id = data.get('verifier_id')
    fields_to_disclose = data.get('fields_to_disclose', [])
    
    if not credential_uuid or not verifier_id:
        return jsonify({"error": "Campi obbligatori mancanti"}), 400
    
    # Ottieni credenziale
    credential = Credential.query.filter_by(uuid=credential_uuid, student_id=current_user.id).first()
    if not credential:
        return jsonify({"error": "Credenziale non trovata"}), 404
    
    # Controlla se la credenziale è revocata
    blockchain = SimpleBlockchain()
    status = blockchain.verify_credential(credential_uuid)
    if status == "revoked":
        return jsonify({
            "error": "Impossibile condividere una credenziale revocata",
            "status": status
        }), 400
    
    # Crea informazione selettiva
    disclosed_data = selective_disclosure(credential, fields_to_disclose)
    
    # In un'app reale, questo verrebbe inviato al verificatore
    # Qui simuliamo con una variabile di sessione
    session['shared_credential'] = {
        "disclosed_data": disclosed_data,
        "verifier_id": verifier_id,
        "shared_by": current_user.username,
        "shared_at": datetime.utcnow().isoformat()
    }
    
    return jsonify({
        "success": True,
        "message": "Credenziale condivisa con successo",
        "disclosed_data": disclosed_data
    })

# Route Università Verificatrice
@app.route('/verifier')
@login_required
def verifier_dashboard():
    if current_user.role != 'verifier':
        flash('Accesso non autorizzato.')
        return redirect(url_for('index'))
    
    # Ottieni credenziale condivisa dalla sessione (questa è una simulazione)
    shared_credential = session.get('shared_credential')
    
    return render_template('verifier.html', 
                          shared_credential=shared_credential)

@app.route('/verifier/verify_credential', methods=['POST'])
@login_required
def verify_credential():
    if current_user.role != 'verifier':
        return jsonify({"error": "Non autorizzato"}), 403
    
    data = request.json
    credential_uuid = data.get('credential_uuid')
    
    if not credential_uuid:
        return jsonify({"error": "Manca credential_uuid"}), 400
    
    # Controlla la blockchain per lo stato della credenziale
    blockchain = SimpleBlockchain()
    status = blockchain.verify_credential(credential_uuid)
    
    # Ottieni risposta OCSP
    ocsp_response = {
        "credential_uuid": credential_uuid
    }
    
    response = app.test_client().post(
        '/api/ocsp/check',
        json=ocsp_response,
        content_type='application/json'
    )
    
    ocsp_result = json.loads(response.data)
    
    # Combina i risultati
    result = {
        "blockchain_status": status,
        "ocsp_status": ocsp_result['responses'][0]['certStatus'],
        "verified_at": datetime.utcnow().isoformat() + "Z",
        "valid": status == "good" and ocsp_result['responses'][0]['certStatus'] == "good"
    }
    
    return jsonify(result)

# Route Autorità di Certificazione
@app.route('/ca')
@login_required
def ca_dashboard():
    if current_user.role != 'ca':
        flash('Accesso non autorizzato.')
        return redirect(url_for('index'))
    
    # Ottieni stato blockchain
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
        return jsonify({"error": "Non autorizzato"}), 403
    
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