# routes/__init__.py
from flask import Blueprint

# Creazione dei Blueprint
auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')
student_bp = Blueprint('student', __name__, url_prefix='/api/student')
university_bp = Blueprint('university', __name__, url_prefix='/api/university')
verifier_bp = Blueprint('verifier', __name__, url_prefix='/api/verifier')

# Importa le route
from .auth_routes import *
from .student_routes import *
from .university_routes import *
from .verifier_routes import *

