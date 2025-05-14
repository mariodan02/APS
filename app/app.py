from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import uuid
import os
import json
import hashlib
import logging

from tls import TLSManager
from x509_utils import X509CertificateManager
from models import db, User, Credential, RevocationRecord, BlockchainBlock, OCSPResponse
from crypto_utils import generate_keypair, sign_data, verify_signature, hash_data, selective_disclosure
from ganache_blockchain import GanacheBlockchain  # Changed from SimpleBlockchain
from ocsp_service import ocsp, init_ocsp_tls

# Configurazione logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'development-key-change-this-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///erasmus_credentials.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configurazione blockchain
app.config['GANACHE_URL'] = 'http://127.0.0.1:7545'  # Default Ganache URL

# Configurazione TLS
app.config['CERT_DIRECTORY'] = os.path.join(os.path.dirname(__file__), 'certificates')
app.config['USE_TLS'] = True
app.logger = logging.getLogger('app')

# Inizializzazione delle estensioni
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Registrazione dei blueprint
app.register_blueprint(ocsp)

@login_manager.user_loader
def load_user(user_id):
    """Carica un utente dal database usando l'ID"""
    return User.query.get(int(user_id))

def setup_tls_for_role(role, university_name=None, country=None):
    """
    Configura i certificati TLS per il ruolo specificato.
    
    Args:
        role: Ruolo dell'utente ('ca', 'issuer', 'verifier', 'student')
        university_name: Nome dell'università (per issuer/verifier)
        country: Paese dell'università (per issuer/verifier)
        
    Returns:
        Istanza di TLSManager configurata per il ruolo
    """
    x509_manager = X509CertificateManager()
    cert_dir = app.config['CERT_DIRECTORY']
    os.makedirs(cert_dir, exist_ok=True)
    
    ca_cert_path = os.path.join(cert_dir, "ca_cert.pem")
    ca_key_path = os.path.join(cert_dir, "ca_key.pem")
    
    # Genera certificato CA se non esiste
    if not os.path.exists(ca_cert_path) or not os.path.exists(ca_key_path):
        ca_cert_path, ca_key_path = x509_manager.generate_ca_certificate()
    
    # Per i ruoli università (issuer/verifier)
    if role in ['issuer', 'verifier'] and university_name and country:
        safe_name = university_name.lower().replace(' ', '_')
        cert_path = os.path.join(cert_dir, f"{safe_name}_cert.pem")
        key_path = os.path.join(cert_dir, f"{safe_name}_key.pem")
        
        # Genera certificato università se non esiste
        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            cert_path, key_path = x509_manager.generate_university_certificate(
                university_name, country, ca_cert_path, ca_key_path
            )
        
        # Crea e restituisce TLSManager
        return TLSManager(cert_path, key_path, ca_cert_path)
    
    # Per CA
    elif role == 'ca':
        return TLSManager(ca_cert_path, ca_key_path, ca_cert_path)
    
    # Per studenti (solo lato client)
    else:
        return TLSManager(ca_path=ca_cert_path)

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
        university_country="FR"
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
        university_country="IT"
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
    blockchain = GanacheBlockchain(app.config['GANACHE_URL'])

# Inizializza database e crea dati di esempio
with app.app_context():
    db.create_all()
    # Controlla se abbiamo già dei dati di esempio
    if User.query.count() == 0:
        create_sample_data()
        
    # Inizializza TLS per la CA
    ca_tls = setup_tls_for_role('ca')
    app.config['CA_TLS'] = ca_tls
    
    # Inizializza TLS per OCSP
    ca_cert_path = os.path.join(app.config['CERT_DIRECTORY'], "ca_cert.pem")
    ca_key_path = os.path.join(app.config['CERT_DIRECTORY'], "ca_key.pem")
    if os.path.exists(ca_cert_path) and os.path.exists(ca_key_path):
        init_ocsp_tls(ca_cert_path, ca_key_path)

# Route
@app.route('/')
def index():
    """Pagina principale dell'applicazione"""
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Gestisce il login degli utenti"""
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
    """Gestisce il logout degli utenti"""
    logout_user()
    return redirect(url_for('index'))

# Route Università Emittente
@app.route('/issuer')
@login_required
def issuer_dashboard():
    """Dashboard per le università emittenti"""
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
    """Emette una nuova credenziale accademica"""
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
    
    # Aggiungi alla blockchain usando TLS
    blockchain = GanacheBlockchain(app.config['GANACHE_URL'])
    
    # Configura TLS per l'università emittente se necessario
    if app.config['USE_TLS']:
        issuer_tls = setup_tls_for_role(
            'issuer', 
            current_user.university_name, 
            current_user.university_country
        )
        
        # Configura la blockchain per usare TLS
        blockchain.init_tls(
            issuer_tls.cert_path, 
            issuer_tls.key_path, 
            issuer_tls.ca_path
        )
        
        try:
            app.logger.info(f"Connessione TLS alla CA per registrare la credenziale {credential.uuid}")
            # In un'implementazione reale, qui ci sarebbe una connessione effettiva
        except Exception as e:
            app.logger.error(f"Errore nella connessione TLS: {e}")
    
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
    """Revoca una credenziale precedentemente emessa"""
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
    
    # Inizializza blockchain con TLS se necessario
    blockchain = GanacheBlockchain(app.config['GANACHE_URL'])
    
    if app.config['USE_TLS']:
        # Inizializza TLS per l'università emittente
        issuer_tls = setup_tls_for_role(
            'issuer', 
            current_user.university_name, 
            current_user.university_country
        )
        
        # Configura blockchain per usare TLS
        blockchain.init_tls(
            issuer_tls.cert_path, 
            issuer_tls.key_path, 
            issuer_tls.ca_path
        )
        
        try:
            app.logger.info(f"Avvio scenario di revoca TLS per credenziale {credential_uuid}")
            # In un'implementazione reale, qui si eseguirebbe lo scenario di revoca TLS
            # issuer_tls.handle_revocation_scenario('ca.edu', 443, credential_uuid, reason)
        except Exception as e:
            app.logger.error(f"Errore nello scenario di revoca TLS: {e}")
    
    # Esegui la revoca nella blockchain
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
    """Dashboard per gli studenti"""
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
    """Visualizza dettagli di una credenziale"""
    if current_user.role != 'student':
        return jsonify({"error": "Non autorizzato"}), 403
    
    credential = Credential.query.filter_by(uuid=uuid, student_id=current_user.id).first()
    if not credential:
        return jsonify({"error": "Credenziale non trovata"}), 404
    
    return jsonify(credential.to_dict())

@app.route('/student/share_credential', methods=['POST'])
@login_required
def share_credential():
    """Condivide una credenziale con un verificatore"""
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
    
    # Configura TLS per lo studente se necessario
    if app.config['USE_TLS']:
        student_tls = setup_tls_for_role('student')
        
        # Configura blockchain per usare TLS
        blockchain = GanacheBlockchain(app.config['GANACHE_URL'])
        blockchain.init_tls(ca_path=student_tls.ca_path)
        
        # Verifica con TLS se la credenziale è revocata
        status = blockchain.verify_credential(credential_uuid)
        if status == "revoked":
            return jsonify({
                "error": "Impossibile condividere una credenziale revocata",
                "status": status
            }), 400
    else:
        # Verifica senza TLS
        blockchain = GanacheBlockchain(app.config['GANACHE_URL'])
        status = blockchain.verify_credential(credential_uuid)
        if status == "revoked":
            return jsonify({
                "error": "Impossibile condividere una credenziale revocata",
                "status": status
            }), 400
    
    # Crea informazione selettiva
    disclosed_data = selective_disclosure(credential, fields_to_disclose)
    
    # In un'app reale, questo verrebbe inviato al verificatore usando TLS
    # Per questa simulazione, usiamo una variabile di sessione
    session['shared_credential'] = {
        "disclosed_data": disclosed_data,
        "verifier_id": verifier_id,
        "shared_by": current_user.username,
        "shared_at": datetime.utcnow().isoformat()
    }
    
    # Se TLS è attivo, logga che si utilizzerebbe TLS per inviare i dati
    if app.config['USE_TLS']:
        verifier = User.query.get(verifier_id)
        app.logger.info(f"Invio dati via TLS a {verifier.university_name if verifier else 'verificatore sconosciuto'}")
    
    return jsonify({
        "success": True,
        "message": "Credenziale condivisa con successo",
        "disclosed_data": disclosed_data
    })

# Route Università Verificatrice
@app.route('/verifier')
@login_required
def verifier_dashboard():
    """Dashboard per le università verificatrici"""
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
    """Verifica l'autenticità di una credenziale"""
    if current_user.role != 'verifier':
        return jsonify({"error": "Non autorizzato"}), 403
    
    data = request.json
    credential_uuid = data.get('credential_uuid')
    
    if not credential_uuid:
        return jsonify({"error": "Manca credential_uuid"}), 400
    
    # Inizializza blockchain con TLS se necessario
    blockchain = GanacheBlockchain(app.config['GANACHE_URL'])
    
    if app.config['USE_TLS']:
        # Inizializza TLS per l'università verificatrice
        verifier_tls = setup_tls_for_role(
            'verifier', 
            current_user.university_name, 
            current_user.university_country
        )
        
        # Configura blockchain per usare TLS
        blockchain.init_tls(
            verifier_tls.cert_path, 
            verifier_tls.key_path, 
            verifier_tls.ca_path
        )
        
        # Log dell'uso di TLS
        app.logger.info(f"Verifica della credenziale {credential_uuid} con TLS")
    
    # Controlla la blockchain per lo stato della credenziale
    status = blockchain.verify_credential(credential_uuid)
    
    # Prepara richiesta OCSP
    ocsp_response = {
        "credential_uuid": credential_uuid
    }
    
    # Invia la richiesta OCSP (in un'app reale userebbe TLS)
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
    """Dashboard per l'autorità di certificazione"""
    if current_user.role != 'ca':
        flash('Accesso non autorizzato.')
        return redirect(url_for('index'))
    
    # Ottieni stato blockchain
    blockchain = GanacheBlockchain(app.config['GANACHE_URL'])
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
    """Restituisce lo stato corrente della blockchain"""
    if current_user.role != 'ca':
        return jsonify({"error": "Non autorizzato"}), 403
    
    # Inizializza blockchain con TLS se necessario
    blockchain = GanacheBlockchain(app.config['GANACHE_URL'])
    
    if app.config['USE_TLS']:
        # Usa il TLS della CA configurato all'avvio
        if 'CA_TLS' in app.config:
            ca_tls = app.config['CA_TLS']
            blockchain.init_tls(
                ca_tls.cert_path, 
                ca_tls.key_path, 
                ca_tls.ca_path
            )
    
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