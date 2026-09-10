import os

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash
)

from database import (
    initialize_database,
    create_user,
    get_user,
    get_all_users,
    add_log,
    get_recent_logs,
    get_security_statistics
)

from security import (
    validate_username,
    validate_password,
    verify_password,
    get_password_strength
)


app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "development-only-secret-change-this"
)

initialize_database()


def get_client_ip():
    return request.remote_addr or "Unknown"


def login_required():
    return "username" in session


def admin_required():
    return session.get("role") == "admin"


@app.route("/")
def home():

    if login_required():
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        valid_username, username_error = validate_username(username)

        if not valid_username:
            flash(username_error, "error")
            return render_template("register.html")

        valid_password, password_error = validate_password(password)

        if not valid_password:
            flash(password_error, "error")
            return render_template("register.html")

        if not create_user(username, password):
            flash("Username already exists.", "error")
            return render_template("register.html")

        add_log(
            username,
            "Account registered",
            get_client_ip()
        )

        flash("Registration successful. Please login.", "success")

        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if login_required():
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = get_user(username)

        if user and verify_password(password, user["password_hash"]):

            session.clear()

            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            add_log(
                username,
                "Successful login",
                get_client_ip()
            )

            return redirect(url_for("dashboard"))

        add_log(
            username or "Unknown",
            "Failed login attempt",
            get_client_ip()
        )

        flash("Invalid username or password.", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():

    username = session.get("username", "Unknown")

    if "username" in session:

        add_log(
            username,
            "Logged out",
            get_client_ip()
        )

    session.clear()

    flash("You have been logged out.", "success")

    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():

    if not login_required():
        flash("Please login to continue.", "error")
        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        username=session["username"],
        role=session["role"]
    )


@app.route("/security")
def security_dashboard():

    if not login_required():
        flash("Please login to continue.", "error")
        return redirect(url_for("login"))

    return render_template(
        "security.html",
        username=session["username"]
    )


@app.route("/admin")
def admin_dashboard():

    if not login_required():
        flash("Please login to continue.", "error")
        return redirect(url_for("login"))

    if not admin_required():
        return render_template(
            "error.html",
            code=403,
            message="You are not authorized to access the administrator area."
        ), 403

    statistics = get_security_statistics()
    users = get_all_users()
    logs = get_recent_logs()

    return render_template(
        "admin.html",
        statistics=statistics,
        users=users,
        logs=logs
    )


@app.errorhandler(404)
def page_not_found(error):

    return render_template(
        "error.html",
        code=404,
        message="The requested page could not be found."
    ), 404


@app.errorhandler(500)
def server_error(error):

    return render_template(
        "error.html",
        code=500,
        message="An internal server error occurred."
    ), 500


if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )