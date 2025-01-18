from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
import random
import bcrypt

app = Flask(__name__)
app.secret_key = "supersecretkey"  # Change this for production

# Database Configuration (Using SQLite for simplicity)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Email Configuration (Replace with actual credentials)
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = "your-email@gmail.com"  # Replace with actual email
app.config["MAIL_PASSWORD"] = "your-email-password"  # Replace with actual app password

db = SQLAlchemy(app)
mail = Mail(app)


# Database Model for Users
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    otp = db.Column(db.String(10), nullable=True)  # Store OTP temporarily for verification
    is_verified = db.Column(db.Boolean, default=False)


# Generate Random OTP
def generate_otp():
    return str(random.randint(100000, 999999))


# Send OTP Email
def send_otp_email(email, otp):
    try:
        msg = Message("KGPMingles OTP Verification", sender="your-email@gmail.com", recipients=[email])
        msg.body = f"Your OTP for KGPMingles registration is: {otp}"
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False


# **Route: Home Page**
@app.route("/")
def home():
    return "Welcome to KGPMingles! <a href='/signup'>Sign Up</a> | <a href='/login'>Login</a>"


# **Route: User Signup**
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form["email"]
        username = request.form["username"]
        password = request.form["password"]

        # Check if user exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email is already registered. Please login!", "danger")
            return redirect(url_for("login"))

        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        otp = generate_otp()

        # Save user to database with OTP (but not yet verified)
        new_user = User(email=email, username=username, password=hashed_password, otp=otp)
        db.session.add(new_user)
        db.session.commit()

        # Send OTP
        if send_otp_email(email, otp):
            flash("OTP sent to your email. Please verify.", "success")
            return redirect(url_for("verify_otp", email=email))
        else:
            flash("Error sending OTP. Try again.", "danger")

    return '''
        <form method="POST">
            Email: <input type="email" name="email" required><br>
            Username: <input type="text" name="username" required><br>
            Password: <input type="password" name="password" required><br>
            <button type="submit">Sign Up</button>
        </form>
    '''


# **Route: OTP Verification**
@app.route("/verify_otp/<email>", methods=["GET", "POST"])
def verify_otp(email):
    user = User.query.filter_by(email=email).first()

    if request.method == "POST":
        entered_otp = request.form["otp"]

        if user and user.otp == entered_otp:
            user.is_verified = True
            user.otp = None  # Remove OTP after verification
            db.session.commit()
            flash("OTP Verified! You can now log in.", "success")
            return redirect(url_for("login"))
        else:
            flash("Invalid OTP. Try again!", "danger")

    return '''
        <form method="POST">
            Enter OTP: <input type="text" name="otp" required><br>
            <button type="submit">Verify OTP</button>
        </form>
    '''


# **Route: User Login**
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.checkpw(password.encode("utf-8"), user.password.encode("utf-8")):
            if not user.is_verified:
                flash("Please verify your email first!", "danger")
                return redirect(url_for("verify_otp", email=user.email))

            session["user"] = user.username
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid username or password!", "danger")

    return '''
        <form method="POST">
            Username: <input type="text" name="username" required><br>
            Password: <input type="password" name="password" required><br>
            <button type="submit">Login</button>
        </form>
    '''


# **Route: User Dashboard (Protected)**
@app.route("/dashboard")
def dashboard():
    if "user" in session:
        return f"Welcome, {session['user']}! <a href='/logout'>Logout</a>"
    else:
        flash("You need to login first!", "warning")
        return redirect(url_for("login"))


# **Route: Logout**
@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# **Initialize Database**
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)
