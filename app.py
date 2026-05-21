from flask import Flask, render_template, request, session, redirect, url_for
from flask_mysqldb import MySQL
from flask_mail import Mail, Message
from functools import wraps
from authlib.integrations.flask_client import OAuth
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import bcrypt
import re
import json
import pyotp  
import qrcode  
import io      
import base64 
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)

app.secret_key = os.getenv('SECRET_KEY')
app.permanent_session_lifetime = timedelta(seconds=10)

app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False

app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')

mysql = MySQL(app)

app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

mail = Mail(app)

serializer = URLSafeTimedSerializer(app.secret_key)

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id = os.getenv('GOOGLE_CLIENT_ID'),
    client_secret = os.getenv('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

intentos_fallidos = {}

def password_seguro(password):
    if len(password) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres"
    if not re.search(r'[A-Z]', password):
        return False, "La contraseña debe tener al menos una mayúscula"
    if not re.search(r'[a-z]', password):
        return False, "La contraseña debe tener al menos una minúscula"
    if not re.search(r'[0-9]', password):
        return False, "La contraseña debe tener al menos un número"
    if not re.search(r'[@$!%*?&#]', password):
        return False, "La contraseña debe tener al menos un símbolo (@$!%*?&#)"
    return True, ""


def guardar_log(usuario_id, usuario_email, rol, accion, ip, navegador):
    with open('logs.txt', 'a', encoding='utf-8') as archivo:
        archivo.write(
            f'{datetime.now()} | '
            f'ID: {usuario_id} | '
            f'Email: {usuario_email} | '
            f'Rol: {rol} | '
            f'IP: {ip} | '
            f'Navegador: {navegador} | '
            f'Acción: {accion}\n'
        )


def generar_token_activacion(email):
    return serializer.dumps(email, salt='email-activacion')


def verificar_token_activacion(token, max_age=900):
    try:
        email = serializer.loads(token, salt='email-activacion', max_age=max_age)
        return email
    except SignatureExpired:
        return None
    except BadSignature:
        return None


def enviar_correo_activacion(email, token):
    link_activacion = url_for('activar_cuenta', token=token, _external=True)
    
    msg = Message(
        subject='🐾 Pet Spa - Activa tu cuenta',
        recipients=[email],
        html=f'''
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #28a745;">🐾 Bienvenido a Pet Spa</h2>
            <p>Gracias por registrarte. Para activar tu cuenta, haz clic en el botón de abajo:</p>
            <br>
            <a href="{link_activacion}" 
               style="background-color: #28a745; color: white; padding: 12px 30px; 
                      text-decoration: none; border-radius: 5px; font-size: 16px;">
                Activar mi cuenta
            </a>
            <br><br>
            <p>O copia y pega este enlace en tu navegador:</p>
            <p style="color: #007bff;">{link_activacion}</p>
            <br>
            <p style="color: #dc3545;">⚠️ Este enlace expira en 15 minutos.</p>
            <hr>
            <p style="color: #999; font-size: 12px;">Si no creaste esta cuenta, ignora este correo.</p>
        </div>
        '''
    )
    mail.send(msg)


def generar_qr_base64(uri):
    """Genera un código QR y lo devuelve como base64 para mostrar en HTML"""
    qr = qrcode.make(uri)
    buf = io.BytesIO()
    qr.save(buf, format='PNG')
    buf.seek(0)
    return base64.b64encode(buf.getvalue()).decode('utf-8')


def rol_requerido(*roles_permitidos):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'usuario_id' not in session:
                return redirect('/')
            if session.get('rol') not in roles_permitidos:
                return render_template('error.html',
                    mensaje='No tienes permisos para acceder a esta página',
                    codigo=403), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator


@app.route('/')
def inicio():
    return render_template("login.html")


@app.route('/login', methods=['POST'])
def login():
    email = request.form['correo'].strip().lower()
    password = request.form['password']
    
    if email in intentos_fallidos and intentos_fallidos[email]['intentos'] >= 5:
        tiempo_bloqueo = datetime.now() - intentos_fallidos[email]['ultimo_intento']
        if tiempo_bloqueo < timedelta(minutes=15):
            return render_template('error.html',
                mensaje='Cuenta bloqueada por 15 minutos. Intente más tarde.',
                codigo=429), 429
        else:
            intentos_fallidos[email] = {'intentos': 0, 'ultimo_intento': datetime.now()}
    
    cursor = mysql.connection.cursor()
    query = """
        SELECT u.id_usuario, u.email, u.password_hash, u.activo, u.email_verificado,
               u.two_factor_enabled, u.two_factor_secret,
               r.nombre as rol, r.permisos
        FROM Usuario u
        JOIN Rol r ON u.id_rol = r.id_rol
        WHERE u.email = %s
    """
    cursor.execute(query, (email,))
    usuario = cursor.fetchone()
    cursor.close()
    
    if usuario:
        (user_id, user_email, password_hash, activo, email_verificado,
         two_factor_enabled, two_factor_secret, rol, permisos) = usuario
        
        if not activo:
            ip = request.remote_addr
            navegador = request.user_agent.string
            guardar_log(user_id, user_email, rol,
                       'Intento de login en cuenta inactiva', ip, navegador)
            return render_template('error.html',
                mensaje='Tu cuenta ha sido desactivada.',
                codigo=403), 403
        
        if rol == 'Cliente' and not email_verificado:
            return render_template('error.html',
                mensaje='Debes verificar tu correo electrónico antes de iniciar sesión.',
                codigo=403), 403
        
        if bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
            
            if rol == 'Admin' and not two_factor_enabled:

                session.permanent = True

                session['usuario_id'] = user_id
                session['usuario_email'] = user_email
                session['rol'] = rol
                session['permisos'] = permisos

                return redirect('/admin/configurar-2fa')
            
            if two_factor_enabled:

                session.permanent = True

                session['temp_user_id'] = user_id
                session['temp_email'] = user_email
                session['temp_rol'] = rol
                session['temp_permisos'] = permisos

                return redirect('/verificar-2fa')
            
            return iniciar_sesion_completa(user_id, user_email, rol, permisos)
    
    ip = request.remote_addr
    navegador = request.user_agent.string
    
    if email not in intentos_fallidos:
        intentos_fallidos[email] = {'intentos': 0, 'ultimo_intento': datetime.now()}
    intentos_fallidos[email]['intentos'] += 1
    intentos_fallidos[email]['ultimo_intento'] = datetime.now()
    
    intentos_restantes = 5 - intentos_fallidos[email]['intentos']
    if intentos_restantes <= 0:
        return render_template('error.html',
            mensaje='Cuenta bloqueada por 15 minutos.',
            codigo=429), 429
    
    return render_template('error.html',
        mensaje=f'Correo o contraseña incorrectos. Te quedan {intentos_restantes} intentos.',
        codigo=401), 401


def iniciar_sesion_completa(user_id, user_email, rol, permisos):
    """Función auxiliar para completar el inicio de sesión"""
    session['usuario_id'] = user_id
    session['usuario_email'] = user_email
    session['rol'] = rol
    session['permisos'] = permisos
    
    session.pop('temp_user_id', None)
    session.pop('temp_email', None)
    session.pop('temp_rol', None)
    session.pop('temp_permisos', None)
    
    ip = request.remote_addr
    navegador = request.user_agent.string
    guardar_log(user_id, user_email, rol, 'Inicio de sesión exitoso', ip, navegador)
    
    cursor = mysql.connection.cursor()
    cursor.execute("UPDATE Usuario SET ultimo_acceso = NOW() WHERE id_usuario = %s", (user_id,))
    mysql.connection.commit()
    cursor.close()
    
    if user_email in intentos_fallidos:
        del intentos_fallidos[user_email]
    
    return redirect('/dashboard')



@app.route('/verificar-2fa', methods=['GET', 'POST'])
def verificar_2fa():
    if 'temp_user_id' not in session:
        return redirect('/')
    
    if request.method == 'GET':
        return render_template('verificar_2fa.html',
            email=session.get('temp_email', ''))
    
    codigo = request.form.get('codigo', '').strip()
    user_id = session['temp_user_id']
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "SELECT two_factor_secret FROM Usuario WHERE id_usuario = %s",
        (user_id,)
    )
    result = cursor.fetchone()
    cursor.close()
    
    if not result or not result[0]:
        session.clear()
        return render_template('error.html', mensaje='Error: 2FA no configurado.', codigo=500), 500
    
    secret = result[0]
    totp = pyotp.TOTP(secret)
    
    if totp.verify(codigo):
        return iniciar_sesion_completa(
            user_id,
            session['temp_email'],
            session['temp_rol'],
            session['temp_permisos']
        )
    else:
        return render_template('verificar_2fa.html',
            email=session.get('temp_email', ''),
            error='Código incorrecto. Intenta de nuevo.')


@app.route('/admin/configurar-2fa')
def configurar_2fa():
    """Página para que el Admin configure su 2FA"""
    if 'usuario_id' not in session or session.get('rol') != 'Admin':
        return redirect('/')
    
    user_id = session['usuario_id']
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "SELECT two_factor_enabled, two_factor_secret, email FROM Usuario WHERE id_usuario = %s",
        (user_id,)
    )
    result = cursor.fetchone()
    cursor.close()
    
    ya_activado, secret_existente, email = result
    
    if ya_activado:
        return redirect('/dashboard')
    
    if not secret_existente:
        secret = pyotp.random_base32()
        cursor = mysql.connection.cursor()
        cursor.execute(
            "UPDATE Usuario SET two_factor_secret = %s WHERE id_usuario = %s",
            (secret, user_id)
        )
        mysql.connection.commit()
        cursor.close()
    else:
        secret = secret_existente
    
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=email,
        issuer_name='Pet Spa'
    )
    
    qr_base64 = generar_qr_base64(totp_uri)
    
    return render_template('configurar_2fa.html',
        qr_code=qr_base64,
        secret=secret,
        email=email)

@app.route('/admin/activar-2fa', methods=['POST'])
def activar_2fa():
    """Activar 2FA después de verificar el código"""
    if 'usuario_id' not in session or session.get('rol') != 'Admin':
        return redirect('/')
    
    codigo = request.form.get('codigo', '').strip()
    user_id = session['usuario_id']
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "SELECT two_factor_secret FROM Usuario WHERE id_usuario = %s",
        (user_id,)
    )
    result = cursor.fetchone()
    cursor.close()
    
    if not result or not result[0]:
        return render_template('error.html',
            mensaje='Primero debes configurar 2FA',
            codigo=400), 400
    
    secret = result[0]
    totp = pyotp.TOTP(secret)
    
    if totp.verify(codigo):
        cursor = mysql.connection.cursor()
        cursor.execute(
            "UPDATE Usuario SET two_factor_enabled = TRUE WHERE id_usuario = %s",
            (user_id,)
        )
        mysql.connection.commit()
        cursor.close()
        
        guardar_log(user_id, session['usuario_email'], 'Admin',
                   '2FA activado exitosamente', request.remote_addr, request.user_agent.string)
        
        return redirect('/dashboard')
    else:
        return render_template('configurar_2fa.html',
            qr_code=generar_qr_base64(pyotp.totp.TOTP(secret).provisioning_uri(
                name=session['usuario_email'], issuer_name='Pet Spa')),
            secret=secret,
            email=session['usuario_email'],
            error='Código incorrecto. Intenta de nuevo.')


@app.route('/registro')
def vista_registro():
    return render_template('registro.html')


@app.route('/registro', methods=['POST'])
def registro():
    nombre = request.form.get('nombre', '').strip()
    correo = request.form.get('correo', '').strip().lower()
    password = request.form.get('password', '')
    
    if not nombre or not correo or not password:
        return render_template('error.html',
            mensaje='Todos los campos son obligatorios',
            codigo=400), 400
    
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', correo):
        return render_template('error.html',
            mensaje='Formato de correo electrónico inválido',
            codigo=400), 400
    
    es_segura, mensaje = password_seguro(password)
    if not es_segura:
        return render_template('error.html', mensaje=mensaje, codigo=400), 400
    
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT id_usuario FROM Usuario WHERE email = %s", (correo,))
    existe = cursor.fetchone()
    
    if existe:
        cursor.close()
        return render_template('error.html',
            mensaje='Este correo electrónico ya está registrado',
            codigo=409), 409
    
    password_hash = bcrypt.hashpw(
        password.encode('utf-8'),
        bcrypt.gensalt()
    ).decode('utf-8')
    
    token = generar_token_activacion(correo)
    token_expiracion = datetime.now() + timedelta(minutes=15)
    
    try:
        query = """
        INSERT INTO Usuario(email, password_hash, id_rol, activo, email_verificado, 
                           token_activacion, token_expiracion)
        VALUES(%s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(query, (correo, password_hash, 4, True, False, token, token_expiracion))
        mysql.connection.commit()
        
        nuevo_id = cursor.lastrowid
        
        try:
            enviar_correo_activacion(correo, token)
        except Exception as e:
            print(f"⚠️ Error al enviar correo: {e}")
        
        ip = request.remote_addr
        navegador = request.user_agent.string
        guardar_log(nuevo_id, correo, 'Cliente',
                   'Registro exitoso - Pendiente verificación', ip, navegador)
        
        cursor.close()
        
        return render_template('exito.html',
            mensaje=f'¡Registro exitoso! 📧 Hemos enviado un enlace de activación a {correo}. '
                   'Revisa tu bandeja de entrada y spam. El enlace expira en 15 minutos.')
        
    except Exception as e:
        cursor.close()
        return render_template('error.html',
            mensaje=f'Error al registrar: {str(e)}',
            codigo=500), 500


@app.route('/activar/<token>')
def activar_cuenta(token):
    email = verificar_token_activacion(token)
    
    if email is None:
        return render_template('error.html',
            mensaje='El enlace de activación ha expirado o es inválido.',
            codigo=410), 410
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "SELECT id_usuario, email_verificado FROM Usuario WHERE email = %s AND token_activacion = %s",
        (email, token)
    )
    usuario = cursor.fetchone()
    
    if not usuario:
        cursor.close()
        return render_template('error.html',
            mensaje='Token de activación no encontrado.',
            codigo=404), 404
    
    user_id, ya_verificado = usuario
    
    if ya_verificado:
        cursor.close()
        return render_template('exito.html',
            mensaje='Tu cuenta ya estaba verificada. Puedes iniciar sesión.')
    
    cursor.execute(
        "UPDATE Usuario SET email_verificado = TRUE, token_activacion = NULL, token_expiracion = NULL WHERE id_usuario = %s",
        (user_id,)
    )
    mysql.connection.commit()
    
    cursor.close()
    
    return render_template('exito.html',
        mensaje='✅ ¡Cuenta activada exitosamente! Ya puedes iniciar sesión.')


@app.route('/reenviar-activacion', methods=['GET', 'POST'])
def reenviar_activacion():
    if request.method == 'GET':
        return render_template('reenviar_activacion.html')
    
    email = request.form.get('correo', '').strip().lower()
    
    cursor = mysql.connection.cursor()
    cursor.execute(
        "SELECT id_usuario, email_verificado FROM Usuario WHERE email = %s AND id_rol = 4",
        (email,)
    )
    usuario = cursor.fetchone()
    
    if not usuario:
        cursor.close()
        return render_template('error.html',
            mensaje='No se encontró una cuenta de cliente con ese correo.',
            codigo=404), 404
    
    user_id, ya_verificado = usuario
    
    if ya_verificado:
        cursor.close()
        return render_template('exito.html',
            mensaje='Tu cuenta ya está verificada.')
    
    token = generar_token_activacion(email)
    token_expiracion = datetime.now() + timedelta(minutes=15)
    
    cursor.execute(
        "UPDATE Usuario SET token_activacion = %s, token_expiracion = %s WHERE id_usuario = %s",
        (token, token_expiracion, user_id)
    )
    mysql.connection.commit()
    cursor.close()
    
    try:
        enviar_correo_activacion(email, token)
        return render_template('exito.html',
            mensaje=f'📧 Se ha reenviado el enlace de activación a {email}.')
    except Exception as e:
        return render_template('error.html',
            mensaje=f'Error al enviar el correo: {str(e)}',
            codigo=500), 500  



@app.route('/login/google')
def login_google():
    session.pop('_google_authlib_state_', None)
    redirect_uri = url_for('callback_google', _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route('/callback/google')
def callback_google():
    try:
        token = google.authorize_access_token()
        resp = google.get('https://www.googleapis.com/oauth2/v3/userinfo')
        user_info = resp.json()
        
        google_email = user_info.get('email')
        
        if not google_email:
            return render_template('error.html',
                mensaje='No se pudo obtener el correo de Google',
                codigo=400), 400
        
        cursor = mysql.connection.cursor()
        cursor.execute(
            "SELECT u.id_usuario, u.email, u.activo, u.email_verificado, r.nombre as rol, r.permisos "
            "FROM Usuario u JOIN Rol r ON u.id_rol = r.id_rol "
            "WHERE u.email = %s", (google_email,)
        )
        usuario = cursor.fetchone()
        
        if usuario:
            user_id, user_email, activo, email_verificado, rol, permisos = usuario
            
            if not activo:
                cursor.close()
                return render_template('error.html', mensaje='Cuenta desactivada.', codigo=403), 403
            
            if not email_verificado:
                cursor.execute("UPDATE Usuario SET email_verificado = TRUE WHERE id_usuario = %s", (user_id,))
                mysql.connection.commit()
            
            session['usuario_id'] = user_id
            session['usuario_email'] = user_email
            session['rol'] = rol
            session['permisos'] = permisos
            
            cursor.execute("UPDATE Usuario SET ultimo_acceso = NOW() WHERE id_usuario = %s", (user_id,))
            mysql.connection.commit()
        else:
            password_aleatorio = bcrypt.hashpw(
                ('google_' + google_email).encode('utf-8'),
                bcrypt.gensalt()
            ).decode('utf-8')
            
            cursor.execute(
                "INSERT INTO Usuario(email, password_hash, id_rol, activo, email_verificado) VALUES(%s, %s, %s, %s, %s)",
                (google_email, password_aleatorio, 4, True, True)
            )
            mysql.connection.commit()
            
            nuevo_id = cursor.lastrowid
            session['usuario_id'] = nuevo_id
            session['usuario_email'] = google_email
            session['rol'] = 'Cliente'
        
        cursor.close()
        return redirect('/dashboard')
        
    except Exception as e:
        print(f"❌ Error Google OAuth: {str(e)}")
        return render_template('error.html',
            mensaje=f'Error en autenticación con Google: {str(e)}',
            codigo=500), 500



@app.route('/dashboard')
def dashboard():
    if 'usuario_id' not in session:
        return redirect('/')
    return render_template('dashboard.html',
        usuario=session.get('usuario_email'),
        rol=session.get('rol'))



@app.route('/admin/crear-personal', methods=['GET', 'POST'])
@rol_requerido('Admin')
def admin_crear_personal():
    if request.method == 'GET':
        return render_template('crear_personal.html')
    
    email = request.form.get('correo', '').strip().lower()
    password = request.form.get('password', '')
    rol_personal = request.form.get('rol')
    nombre = request.form.get('nombre', '').strip()
    especialidad = request.form.get('especialidad', '')
    telefono = request.form.get('telefono', '')
    turno = request.form.get('turno', '')
    
    if rol_personal not in ['Recepción', 'Groomer']:
        return render_template('error.html', mensaje='Rol inválido', codigo=400), 400
    
    es_segura, mensaje = password_seguro(password)
    if not es_segura:
        return render_template('error.html', mensaje=mensaje, codigo=400), 400
    
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT id_rol FROM Rol WHERE nombre = %s", (rol_personal,))
    rol_data = cursor.fetchone()
    
    if not rol_data:
        cursor.close()
        return render_template('error.html', mensaje='Rol no encontrado', codigo=500), 500
    
    id_rol = rol_data[0]
    
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    try:
        cursor.execute(
            "INSERT INTO Usuario(email, password_hash, id_rol, activo, email_verificado) VALUES(%s, %s, %s, %s, %s)",
            (email, password_hash, id_rol, True, True)
        )
        
        if rol_personal == 'Groomer':
            nuevo_id = cursor.lastrowid
            cursor.execute(
                "INSERT INTO Groomer(nombre, especialidad, id_usuario, activo) VALUES(%s, %s, %s, %s)",
                (nombre, especialidad, nuevo_id, True)
            )
        
        mysql.connection.commit()
        cursor.close()
        return render_template('exito.html', mensaje=f'Usuario {rol_personal} creado exitosamente')
        
    except Exception as e:
        mysql.connection.rollback()
        cursor.close()
        return render_template('error.html', mensaje=f'Error: {str(e)}', codigo=500), 500


@app.route('/logout')
def logout():
    if 'usuario_id' in session:
        guardar_log(session['usuario_id'], session.get('usuario_email', 'N/A'),
                   session.get('rol', 'N/A'), 'Cierre de sesión', 
                   request.remote_addr, request.user_agent.string)
    session.clear()
    return redirect('/')


@app.errorhandler(404)
def no_encontrado(e):
    return render_template('error.html', mensaje='Página no encontrada', codigo=404), 404

@app.route('/admin/desactivar-usuario/<int:user_id>', methods=['POST'])
@rol_requerido('Admin')
def desactivar_usuario(user_id):
    """Desactiva un usuario (borrado lógico)"""
    cursor = mysql.connection.cursor()
    
    cursor.execute("SELECT email, id_rol FROM Usuario WHERE id_usuario = %s", (user_id,))
    usuario = cursor.fetchone()
    
    if not usuario:
        cursor.close()
        return render_template('error.html',
            mensaje='Usuario no encontrado',
            codigo=404), 404
    
    email, id_rol = usuario
    
    if user_id == session['usuario_id']:
        cursor.close()
        return render_template('error.html',
            mensaje='No puedes desactivar tu propia cuenta',
            codigo=400), 400
    
    cursor.execute("UPDATE Usuario SET activo = FALSE WHERE id_usuario = %s", (user_id,))
    mysql.connection.commit()
    
    guardar_log(session['usuario_id'], session['usuario_email'], 'Admin',
               f'Desactivación de usuario ID:{user_id} - {email}',
               request.remote_addr, request.user_agent.string)
    
    cursor.close()
    
    return render_template('exito.html',
        mensaje=f'✅ Usuario {email} desactivado exitosamente.')
    
@app.route('/admin/logs')
@rol_requerido('Admin')
def ver_logs():
    """Muestra los logs de auditoría al Admin"""
    try:
        with open('logs.txt', 'r', encoding='utf-8') as archivo:
            lineas = archivo.readlines()
        
        logs = lineas[-100:]
        logs.reverse()
        
        return render_template('ver_logs.html', logs=logs)
    except FileNotFoundError:
        return render_template('ver_logs.html', logs=[])
    
@app.route('/admin/usuarios')
@rol_requerido('Admin')
def listar_usuarios():
    """Lista todos los usuarios para gestionarlos"""
    cursor = mysql.connection.cursor()
    cursor.execute("""
        SELECT u.id_usuario, u.email, u.activo, r.nombre as rol
        FROM Usuario u
        JOIN Rol r ON u.id_rol = r.id_rol
        ORDER BY u.id_usuario
    """)
    usuarios = cursor.fetchall()
    cursor.close()
    
    return render_template('listar_usuarios.html', usuarios=usuarios)

if __name__ == '__main__':
    app.run(debug=True, port=5000)