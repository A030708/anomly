from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from datetime import datetime, timezone
import os

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


class FakeForm:
    def hidden_tag(self):
        return ""


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        password = request.form.get("password")
        if password == os.getenv("SENTINEL_ADMIN_PASS", "1234567890"):
            session["sentinel_admin"] = True
            session["username"] = "admin"
            session["role"] = "SOC Analyst"
            session["login_time"] = datetime.now(timezone.utc).isoformat()
            flash("Welcome back, Admin", "success")
            return redirect(url_for("dashboard.index"))
        flash("Invalid password", "error")
    return render_template("login.html", form=FakeForm())


@auth_bp.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully", "info")
    return redirect(url_for("auth.login"))
