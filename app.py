from flask import Flask, render_template, request, redirect, url_for, session, flash
import pymysql
pymysql.install_as_MySQLdb()
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import os
from werkzeug.utils import secure_filename




app = Flask(__name__)
app.secret_key = "clave_secreta"

# 🔹 Configuración de MySQL
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost/sakil'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Configuración de correo (ejemplo con Gmail)

app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = "tu_correo@gmail.com"
app.config["MAIL_PASSWORD"] = "tu_contraseña_de_aplicacion"  # contraseña generada en Google
app.config["MAIL_DEFAULT_SENDER"] = "tu_correo@gmail.com"
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")


mail = Mail(app)

# Serializer para tokens
s = URLSafeTimedSerializer(app.secret_key)

# Carpeta donde se guardarán las imágenes
UPLOAD_FOLDER = os.path.join(app.root_path, "static", "img")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

#Modelo rol
class Rol(db.Model):
    __tablename__ = "rol"
    id_rol = db.Column(db.Integer, primary_key=True)
    rol = db.Column(db.Text, nullable=False)

class Usuario(db.Model):
    __tablename__ = "usuario"
    id_cliente = db.Column(db.Integer, primary_key=True, autoincrement=True)
    nombre = db.Column(db.Text, nullable=False)
    apellido = db.Column(db.Text, nullable=False)
    ciudad = db.Column(db.Text, nullable=False)
    direccion = db.Column(db.String(20), nullable=False)
    fecha_nac = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(30), nullable=False, unique=True)
    telefono = db.Column(db.Integer, nullable=False)
    contraseña = db.Column(db.String(255), nullable=False)
    id_rol = db.Column(db.Integer, db.ForeignKey("rol.id_rol"), nullable=False)
    estado = db.Column(db.Boolean, default=True)
    
    # Campos nuevos:
    intentos_fallidos = db.Column(db.Integer, default=0)
    bloqueado = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"<Usuario {self.nombre} {self.apellido}>"


# Modelo de la tabla productos
class Producto(db.Model):
    __tablename__ = "productos"
    id_producto = db.Column(db.Integer, primary_key=True)
    nom_producto = db.Column(db.Text, nullable=False)
    descripcion = db.Column(db.Text, nullable=False)
    stok = db.Column(db.Integer, nullable=False)
    id_categoria = db.Column(db.Integer, db.ForeignKey("categoria.id_categoria"), nullable=False)
    precio_producto = db.Column(db.String(20), nullable=False)
    #nueva columna foto
    foto = db.Column(db.String(255), nullable=True)



    def __repr__(self):
        return f"<Producto {self.nom_producto}>"

# Modelo de la tabla categoria
class Categoria(db.Model):
    __tablename__ = "categoria"
    id_categoria = db.Column(db.Integer, primary_key=True)
    nom_categoria = db.Column(db.Text, nullable=False)

    # Relación con productos (sí existe en tu SQL)
    productos = db.relationship("Producto", backref="categoria", lazy=True)





# ------------------- RUTAS -------------------

@app.route("/")
def home():
    mensaje = session.get("usuario", None)
    return render_template("home.html", mensaje=mensaje)


# LOGIN
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        usuario = Usuario.query.filter_by(email=email).first()

        if not usuario:
            return render_template("login.html", error="Credenciales inválidas")

        if usuario.bloqueado:
            return render_template("login.html", error="Cuenta bloqueada por múltiples intentos fallidos.")

        if check_password_hash(str(usuario.contraseña), password):
            # Login correcto: reiniciamos intentos
            usuario.intentos_fallidos = 0
            db.session.commit()
            session["usuario"] = f"{usuario.nombre} {usuario.apellido}"
            flash("Has iniciado sesión correctamente", "success")
            return redirect(url_for("home"))
        else:
            # Incrementamos intentos fallidos
            usuario.intentos_fallidos += 1

            if usuario.intentos_fallidos >= 3:
                usuario.bloqueado = True
                db.session.commit()
                return render_template("login.html", error="Cuenta bloqueada por múltiples intentos fallidos.")
            else:
                db.session.commit()
                intentos_restantes = 3 - usuario.intentos_fallidos
                return render_template("login.html", error=f"Contraseña incorrecta. Te quedan {intentos_restantes} intento(s).")

    return render_template("login.html")






# OLVIDE MI CONTRASEÑA
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        usuario = Usuario.query.filter_by(email=email).first()

        if usuario:
            # Crear token y enlace
            token = s.dumps(email, salt="password-reset-salt")
            reset_url = url_for("reset_password", token=token, _external=True)

            # 🚨 Flash con botón HTML en vez de URL cruda
            flash(
                f"""<p>Este sería el enlace enviado a tu correo:</p>
                <a href='{reset_url}' class='btn btn-primary mt-2'>Restablecer Contraseña</a>""",
                "info"
            )
            return redirect(url_for("login"))

        flash("El correo no está registrado.", "danger")

    return render_template("forgot_password.html")
    

#Resetear contraseña
@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        email = s.loads(token, salt="password-reset-salt", max_age=1800)  # 30 min
    except:
        flash("El enlace de recuperación ha expirado o es inválido.", "danger")
        return redirect(url_for("forgot_password"))

    usuario = Usuario.query.filter_by(email=email).first_or_404()

    if request.method == "POST":
        new_pwd = request.form["password"]
        usuario.password = generate_password_hash(new_pwd)
        db.session.commit()
        flash("Tu contraseña ha sido restablecida con éxito.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", email=email)




# REGISTRO
@app.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        nombre = request.form["nombre"].strip()
        apellido = request.form["apellido"].strip()
        email = request.form["email"].strip().lower()
        raw_password = request.form["password"]

        # Verificar si ya existe el email
        if Usuario.query.filter_by(email=email).first():
            return render_template("registro.html", error="El correo ya está registrado")

        hashed_password = generate_password_hash(raw_password)

        nuevo_usuario = Usuario(
            nombre=nombre,
            apellido=apellido,
            ciudad="",
            direccion="",
            fecha_nac="",
            email=email,
            telefono=0,
            contraseña=hashed_password,
            id_rol=2,  # Por ejemplo, 2 = cliente
            estado=True
        )

        db.session.add(nuevo_usuario)
        db.session.commit()
        flash("Usuario registrado con éxito", "success")
        return redirect(url_for("listar_usuarios"))

    return render_template("registro.html")


# LISTAR USUARIOS
@app.route("/usuarios")
def listar_usuarios():
    usuarios = Usuario.query.all()
    return render_template("usuarios.html", usuarios=usuarios)


# EDITAR USUARIO
@app.route("/editar/<int:id_cliente>", methods=["GET", "POST"])
def editar_usuario(id_cliente):
    usuario = Usuario.query.get_or_404(id_cliente)
    ...



    if request.method == "POST":
        usuario.username = request.form["username"].strip()
        usuario.email = request.form["email"].strip().lower()

        new_pwd = request.form["password"]
        if new_pwd.strip():  # Solo si el usuario escribió algo
            usuario.password = generate_password_hash(new_pwd)

        db.session.commit()
        flash("Usuario actualizado correctamente", "info")
        return redirect(url_for("listar_usuarios"))

    return render_template("editar.html", usuario=usuario)


# ELIMINAR USUARIO
@app.route("/eliminar/<int:id_cliente>")
def eliminar_usuario(id_cliente):
    usuario = Usuario.query.get_or_404(id_cliente)
    db.session.delete(usuario)
    db.session.commit()
    flash("Usuario eliminado correctamente", "danger")
    return redirect(url_for("listar_usuarios"))



# LOGOUT
@app.route("/logout")
def logout():
    session.pop("usuario", None)
    flash("Sesión cerrada", "warning")
    return redirect(url_for("home"))

#RUTAS ADMIN-----------
# 📌 Listar productos
@app.route("/admin/productos")
def admin_productos():
    productos = Producto.query.all()
    categorias = Categoria.query.all()
    return render_template(
        "admin_productos.html",
        productos=productos,
        categorias=categorias
    )


# 📌 Crear producto
@app.route("/admin/productos/nuevo", methods=["GET", "POST"])
def nuevo_producto():
    categorias = Categoria.query.all()
    
    if request.method == "POST":
        nom_producto = request.form["nom_producto"]
        descripcion = request.form["descripcion"]
        precio = request.form["precio_producto"]
        stok = request.form["stok"]
        id_categoria = request.form["id_categoria"]

        # Manejo de imagen
        file = request.files["foto"]
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
        else:
            filename = "default.jpg"  # Imagen por defecto

        nuevo = Producto(
            nom_producto=nom_producto,
            descripcion=descripcion,
            precio_producto=precio,
            stok=stok,
            id_categoria=id_categoria,
            foto=filename
        )

        db.session.add(nuevo)
        db.session.commit()
        flash("Producto agregado con éxito", "success")
        return redirect(url_for("admin_productos"))

    return render_template("form_producto.html", accion="Crear", producto=None, categorias=categorias)




# 📌 Editar producto
@app.route("/admin/productos/editar/<int:id>", methods=["GET", "POST"])
def editar_producto(id):
    producto = Producto.query.get_or_404(id)
    categorias = Categoria.query.all()

    if request.method == "POST":
        producto.nom_producto = request.form["nom_producto"]
        producto.descripcion = request.form["descripcion"]
        producto.precio_producto = request.form["precio_producto"]
        producto.stok = request.form["stok"]
        producto.id_categoria = request.form["id_categoria"]

        # Manejo de imagen
        file = request.files["foto"]
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            producto.foto = filename  # Actualizamos la foto solo si se sube una nueva

        db.session.commit()
        flash("Producto actualizado con éxito", "info")
        return redirect(url_for("admin_productos"))

    return render_template("form_producto.html", accion="Editar", producto=producto, categorias=categorias)


# 📌 Eliminar producto
@app.route("/admin/productos/eliminar/<int:id>", methods=["POST"])
def eliminar_producto(id):
    producto = Producto.query.get_or_404(id)
    db.session.delete(producto)
    db.session.commit()
    flash("🗑️ Producto eliminado con éxito", "danger")
    return redirect(url_for("admin_productos"))


# -----------------------------------------
#---------------------------------
#RUTAS catalogo publico
#------------------- RUTAS -------------------
# ==========================
# RUTAS CATÁLOGO PÚBLICO
# ==========================

@app.route("/catalogo")
def catalogo():
    productos = Producto.query.all()
    categorias = Categoria.query.all()
    return render_template(
        "catalogo.html",
        productos=productos,
        categorias=categorias
    )


@app.route("/carrito/agregar/<int:id>")
def agregar_carrito(id):
    producto = Producto.query.get_or_404(id)

    # Inicializamos carrito en sesión si no existe
    if "carrito" not in session:
        session["carrito"] = {}

    carrito = session["carrito"]

    # Si ya existe el producto en el carrito, sumamos cantidad
    if str(id) in carrito:
        carrito[str(id)]["cantidad"] += 1
    else:
        carrito[str(id)] = {
            "id": producto.id_producto,
            "nombre": producto.nom_producto,
            "precio": float(producto.precio_producto),
            "cantidad": 1
        }

    session["carrito"] = carrito
    flash(f"🛒 {producto.nom_producto} agregado al carrito", "success")
    return redirect(url_for("catalogo"))


@app.route("/carrito")
def ver_carrito():
    carrito = session.get("carrito", {})
    total = sum(item["precio"] * item["cantidad"] for item in carrito.values())
    return render_template("carrito.html", carrito=carrito, total=total)


@app.route("/carrito/vaciar")
def vaciar_carrito():
    session.pop("carrito", None)
    flash("🧹 Carrito vaciado", "info")
    return redirect(url_for("catalogo"))



@app.route("/admin/desbloquear/<int:id_cliente>")
def desbloquear_usuario(id_cliente):
    usuario = Usuario.query.get_or_404(id_cliente)
    usuario.intentos_fallidos = 0
    usuario.bloqueado = False
    db.session.commit()
    flash("Usuario desbloqueado", "info")
    return redirect(url_for("listar_usuarios"))



# ------------------- FIN RUTAS -------------------


if __name__ == "__main__":
    app.run(debug=True)
