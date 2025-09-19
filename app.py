from flask import Flask, render_template, request, redirect, url_for, session, flash
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "clave_secreta"  


db_config = {
    "host": "localhost",
    "user": "root",     
    "password": "",     
    "database": "flask_login"
}

def get_db_connection():
    return mysql.connector.connect(**db_config)


@app.route("/")
def home():
    if "username" in session:
        return render_template("home.html", username=session["username"])
    return redirect(url_for("login"))



@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        cursor.close()
        conn.close()

        if user:
            if not user["is_active"]:
                flash("Tu cuenta está desactivada ❌ Contacta con el administrador.")
            elif check_password_hash(user["password"], password):
                session["username"] = user["username"]
                flash("Has iniciado sesión correctamente ✅")
                return redirect(url_for("home"))
            else:
                flash("Usuario o contraseña incorrectos ❌")
        else:
            flash("Usuario o contraseña incorrectos ❌")

    return render_template("login.html")



@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

    
        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", 
                    (username, hashed_password))
            conn.commit()
            flash("Usuario registrado correctamente ✅ Ya puedes iniciar sesión")
            return redirect(url_for("login"))
        except mysql.connector.IntegrityError:
            flash("⚠️ El usuario ya existe, intenta con otro.")
        finally:
            cursor.close()
            conn.close()

    return render_template("register.html")




@app.route("/logout")
def logout():
    session.pop("username", None)
    flash("Has cerrado sesión 👋")
    return redirect(url_for("login"))

@app.route("/users")
def list_users():
    if "username" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT id, username, is_active FROM users")
    users = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("users.html", users=users)




@app.route("/users/create", methods=["GET", "POST"])
def create_user():
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        username = request.form["username"]
        password = generate_password_hash(request.form["password"])

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, password))
            conn.commit()
            flash("Usuario creado exitosamente ✅")
            return redirect(url_for("list_users"))
        except mysql.connector.IntegrityError:
            flash("⚠️ El usuario ya existe.")
        finally:
            cursor.close()
            conn.close()

    return render_template("create_user.html")

@app.route("/users/edit/<int:user_id>", methods=["GET", "POST"])
def edit_user(user_id):
    if "username" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        is_active = 1 if request.form.get("is_active") == "1" else 0

        if password:
            hashed_password = generate_password_hash(password)
            cursor.execute(
                "UPDATE users SET username = %s, password = %s, is_active = %s WHERE id = %s",
                (username, hashed_password, is_active, user_id)
            )
        else:
            cursor.execute(
                "UPDATE users SET username = %s, is_active = %s WHERE id = %s",
                (username, is_active, user_id)
            )

        conn.commit()
        flash("Usuario actualizado correctamente ✅")
        cursor.close()
        conn.close()
        return redirect(url_for("list_users"))

    # Mostrar datos actuales si es GET
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    return render_template("edit_user.html", user=user)




@app.route("/users/delete/<int:user_id>", methods=["POST"])
def delete_user(user_id):
    if "username" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
    conn.commit()

    cursor.close()
    conn.close()

    flash("Usuario eliminado correctamente 🗑️")
    return redirect(url_for("list_users"))




@app.route("/users/toggle_status/<int:user_id>", methods=["POST"])
def toggle_user_status(user_id):
    if "username" not in session:
        return redirect(url_for("login"))

    action = request.form["action"]
    new_status = 1 if action == "activate" else 0

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("UPDATE users SET is_active = %s WHERE id = %s", (new_status, user_id))
    conn.commit()

    cursor.close()
    conn.close()

    estado = "activado ✅" if new_status else "desactivado ❌"
    flash(f"Usuario {estado} correctamente.")
    return redirect(url_for("list_users"))



@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form["username"]

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user:
            flash("Usuario encontrado ✅ Ingresa tu nueva contraseña.")
            return redirect(url_for("reset_password", username=username))
        else:
            flash("❌ Usuario no encontrado.")

    return render_template("forgot_password.html")


@app.route("/reset_password/<username>", methods=["GET", "POST"])
def reset_password(username):
    if request.method == "POST":
        new_password = request.form["password"]
        hashed_password = generate_password_hash(new_password)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password = %s WHERE username = %s", (hashed_password, username))
        conn.commit()
        cursor.close()
        conn.close()

        flash("Contraseña actualizada correctamente ✅ Ya puedes iniciar sesión.")
        return redirect(url_for("login"))

    return render_template("reset_password.html", username=username)


@app.route("/catalogo")
def catalogo():
    if "username" not in session:  # Solo usuarios logueados pueden ver el catálogo
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM perfumes")
    perfumes = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template("catalogo.html", perfumes=perfumes)


@app.route("/catalogo/agregar", methods=["GET", "POST"])
def agregar_perfume():
    if "username" not in session: 
        return redirect(url_for("login"))

    if request.method == "POST":
        nombre = request.form["nombre"]
        marca = request.form["marca"]
        descripcion = request.form["descripcion"]
        precio = request.form["precio"]
        imagen_url = request.form["imagen_url"]

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO perfumes (nombre, marca, descripcion, precio, imagen_url) VALUES (%s, %s, %s, %s, %s)",
            (nombre, marca, descripcion, precio, imagen_url)
        )
        conn.commit()
        cursor.close()
        conn.close()

        flash("Perfume agregado correctamente ✅")
        return redirect(url_for("catalogo"))

    return render_template("agregar_perfume.html")


if __name__ == "__main__":
    app.run(debug=True)


