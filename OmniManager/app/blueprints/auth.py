from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from app.extensions import db, limiter
from app.models.user import User
from app.utils.audit import log_action

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("20 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        remember = bool(request.form.get("remember"))

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            if user.totp_enabled:
                session["pending_2fa_user_id"] = user.id
                session["pending_2fa_remember"] = remember
                return redirect(url_for("auth.verify_2fa"))
            user.last_login = datetime.utcnow()
            db.session.commit()
            login_user(user, remember=remember)
            log_action("login.success", object_type="user", object_id=user.id,
                       detail=f"User '{username}' logged in")
            next_page = request.args.get("next")
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(next_page or url_for("dashboard.index"))

        log_action("login.fail", detail=f"Failed login attempt for username '{username}'",
                   actor_name=username)
        flash("Invalid username or password.", "danger")

    return render_template("auth/login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    log_action("logout", object_type="user", object_id=current_user.id)
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")

        if email and email != current_user.email:
            if User.query.filter_by(email=email).first():
                flash("Email already in use.", "danger")
                return redirect(url_for("auth.profile"))
            current_user.email = email

        if new_password:
            if not current_user.check_password(current_password):
                flash("Current password is incorrect.", "danger")
                return redirect(url_for("auth.profile"))
            current_user.set_password(new_password)

        db.session.commit()
        log_action("user.profile_update", object_type="user", object_id=current_user.id)
        flash("Profile updated.", "success")
        return redirect(url_for("auth.profile"))

    return render_template("auth/profile.html")


@auth_bp.route("/users")
@login_required
def users():
    if not current_user.is_admin:
        flash("Admin access required.", "danger")
        return redirect(url_for("dashboard.index"))
    all_users = User.query.order_by(User.username).all()
    return render_template("auth/users.html", users=all_users)


@auth_bp.route("/users/create", methods=["GET", "POST"])
@login_required
def create_user():
    if not current_user.is_admin:
        flash("Admin access required.", "danger")
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        is_admin = bool(request.form.get("is_admin"))

        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return redirect(url_for("auth.create_user"))

        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
            return redirect(url_for("auth.create_user"))

        user = User(username=username, email=email, is_admin=is_admin)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        log_action("user.create", object_type="user", object_id=user.id,
                   detail=f"Created user '{username}'")
        flash(f"User '{username}' created.", "success")
        return redirect(url_for("auth.users"))

    return render_template("auth/create_user.html")


@auth_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash("Admin access required.", "danger")
        return redirect(url_for("dashboard.index"))

    user = db.get_or_404(User, user_id)
    if user.id == current_user.id:
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("auth.users"))

    username = user.username
    db.session.delete(user)
    db.session.commit()
    log_action("user.delete", object_type="user", object_id=user_id,
               detail=f"Deleted user '{username}'")
    flash(f"User '{username}' deleted.", "success")
    return redirect(url_for("auth.users"))


# ── Password reset ────────────────────────────────────────────────────────────

@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = User.query.filter(db.func.lower(User.email) == email).first()

        # Always show the same message to prevent email enumeration
        if user:
            from app.models.password_reset_token import PasswordResetToken
            from app.utils.mailer import send_password_reset
            token_obj = PasswordResetToken.create_for(user)
            reset_url = url_for("auth.reset_password", token=token_obj.token, _external=True)
            sent = send_password_reset(user.email, reset_url)
            if not sent:
                # SMTP not configured — surface the link for admin use
                flash(
                    f"SMTP not configured. Reset link (share securely): {reset_url}",
                    "warning",
                )
                return redirect(url_for("auth.login"))
            log_action("password_reset.requested", object_type="user",
                       object_id=user.id, actor_name=user.username)

        flash("If that email is registered, a reset link has been sent.", "info")
        return redirect(url_for("auth.login"))

    return render_template("auth/forgot_password.html")


@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    from app.models.password_reset_token import PasswordResetToken
    token_obj = PasswordResetToken.find_valid(token)
    if not token_obj:
        flash("This reset link is invalid or has expired.", "danger")
        return redirect(url_for("auth.forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "")

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return render_template("auth/reset_password.html", token=token)
        if password != password2:
            flash("Passwords do not match.", "danger")
            return render_template("auth/reset_password.html", token=token)

        user = db.session.get(User, token_obj.user_id)
        if not user:
            flash("User not found.", "danger")
            return redirect(url_for("auth.login"))

        user.set_password(password)
        db.session.commit()
        token_obj.consume()
        log_action("password_reset.complete", object_type="user",
                   object_id=user.id, actor_name=user.username)
        flash("Password updated. You can now log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/reset_password.html", token=token)


# ── 2FA ───────────────────────────────────────────────────────────────────────

@auth_bp.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    user_id = session.get("pending_2fa_user_id")
    if not user_id:
        return redirect(url_for("auth.login"))
    user = db.session.get(User, user_id)
    if not user:
        session.pop("pending_2fa_user_id", None)
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        token = request.form.get("token", "").strip().replace(" ", "")
        if user.verify_totp(token):
            session.pop("pending_2fa_user_id", None)
            remember = session.pop("pending_2fa_remember", False)
            user.last_login = datetime.utcnow()
            db.session.commit()
            login_user(user, remember=remember)
            log_action("login.success", object_type="user", object_id=user.id,
                       detail=f"User '{user.username}' logged in (2FA)")
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(url_for("dashboard.index"))
        flash("Invalid authenticator code.", "danger")

    return render_template("auth/verify_2fa.html")


@auth_bp.route("/setup-2fa", methods=["GET", "POST"])
@login_required
def setup_2fa():
    import pyotp, qrcode, io, base64

    if request.method == "POST":
        action = request.form.get("action")
        if action == "disable":
            current_user.totp_secret = None
            current_user.totp_enabled = False
            db.session.commit()
            log_action("2fa.disable", object_type="user", object_id=current_user.id)
            flash("Two-factor authentication disabled.", "info")
            return redirect(url_for("auth.profile"))

        token = request.form.get("token", "").strip().replace(" ", "")
        raw_secret = request.form.get("raw_secret", "")
        totp = pyotp.TOTP(raw_secret)
        if totp.verify(token, valid_window=1):
            current_user.set_totp_secret(raw_secret)
            current_user.totp_enabled = True
            db.session.commit()
            log_action("2fa.enable", object_type="user", object_id=current_user.id)
            flash("Two-factor authentication enabled!", "success")
            return redirect(url_for("auth.profile"))
        flash("Invalid code — please try again.", "danger")
        return redirect(url_for("auth.setup_2fa"))

    raw_secret = pyotp.random_base32()
    totp_uri = pyotp.totp.TOTP(raw_secret).provisioning_uri(
        name=current_user.email,
        issuer_name="OmniManager",
    )
    img = qrcode.make(totp_uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()
    return render_template("auth/setup_2fa.html", raw_secret=raw_secret, qr_b64=qr_b64)
