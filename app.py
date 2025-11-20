from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import tempfile
import mimetypes
from functools import wraps
from sqlalchemy.orm import joinedload


from security import (
    snowflake_generator,
    file_hasher,
    file_encryptor,
    hash_file_bytes,
    DeduplicationManager,
)


# App Config

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-change-this")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URI", "sqlite:///medivault.db")
app.config["UPLOAD_FOLDER"] = os.getenv("UPLOAD_FOLDER", "uploads")
app.config["ENCRYPTED_FOLDER"] = os.getenv("ENCRYPTED_FOLDER", "encrypted_files")
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_CONTENT_MB", "16")) * 1024 * 1024


from datetime import timedelta
SESSION_DAYS = int(os.getenv("SESSION_DAYS", "14"))
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=SESSION_DAYS)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = os.getenv("SESSION_COOKIE_SECURE", "0") == "1"

# File type 
ALLOWED_EXTENSIONS = {
    "pdf","png","jpg","jpeg","gif","bmp","tiff","txt","csv","doc","docx","xls","xlsx","ppt","pptx"
}
ALLOWED_MIMETYPES = {
    "application/pdf","image/png","image/jpeg","image/gif","image/bmp","image/tiff","text/plain",
    "text/csv","application/vnd.ms-excel","application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/msword","application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-powerpoint","application/vnd.openxmlformats-officedocument.presentationml.presentation",
}

db = SQLAlchemy(app)

# Ensure storage
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
os.makedirs(app.config["ENCRYPTED_FOLDER"], exist_ok=True)





def ext_ok(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def mime_ok(stream, fallback_name: str) -> bool:
   
    mt = getattr(stream, "mimetype", None) or mimetypes.guess_type(fallback_name)[0]
    return (mt in ALLOWED_MIMETYPES) if mt else True


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login first", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def doctor_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "doctor_id" not in session:
            flash("Doctor login required", "warning")
            return redirect(url_for("doctor_login"))
        return f(*args, **kwargs)
    return wrapper

@app.before_request
def security_headers_and_session():
   
    session.permanent = True

@app.after_request
def set_secure_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
    return resp


from datetime import timedelta

def has_active_consent(patient_id: int, doctor_id: int) -> bool:
    now = datetime.utcnow()
    c = (
        Consent.query.filter_by(patient_id=patient_id, doctor_id=doctor_id, status="approved")
        .order_by(Consent.id.desc())
        .first()
    )
    return bool(c and c.approved_until and c.approved_until >= now)


# Models

class Patient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    snowflake_id = db.Column(db.BigInteger, unique=True, nullable=False, index=True)
    govt_id = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    dob = db.Column(db.Date, nullable=False)
    blood_group = db.Column(db.String(5))
    phone = db.Column(db.String(15))
    address = db.Column(db.Text)
    emergency_contact = db.Column(db.String(15))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    records = db.relationship("MedicalRecord", backref="patient", lazy=True, cascade="all, delete-orphan")
    prescriptions = db.relationship("Prescription", backref="patient", lazy=True, cascade="all, delete-orphan")

class Doctor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    snowflake_id = db.Column(db.BigInteger, unique=True, nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    specialization = db.Column(db.String(100))
    license_number = db.Column(db.String(50), unique=True)
    hospital = db.Column(db.String(200))
    phone = db.Column(db.String(15))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class MedicalRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    snowflake_id = db.Column(db.BigInteger, unique=True, nullable=False, index=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patient.id"), nullable=False)
    record_type = db.Column(db.String(50), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    filename = db.Column(db.String(300))  # path to encrypted file on disk
    file_hash = db.Column(db.String(64), index=True)
    file_size = db.Column(db.Integer)
    is_encrypted = db.Column(db.Boolean, default=True)
    uploaded_by = db.Column(db.String(100))
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    test_date = db.Column(db.Date)

class Prescription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    snowflake_id = db.Column(db.BigInteger, unique=True, nullable=False, index=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patient.id"), nullable=False)
    doctor_name = db.Column(db.String(100), nullable=False)
    hospital = db.Column(db.String(200))
    diagnosis = db.Column(db.Text)
    medications = db.Column(db.Text)
    instructions = db.Column(db.Text)
    prescription_date = db.Column(db.Date, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patient.id"), nullable=False)
    accessed_by = db.Column(db.String(100), nullable=False)
    access_type = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(50))

class Consent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patient.id"), nullable=False, index=True)
    doctor_id = db.Column(db.Integer, db.ForeignKey("doctor.id"), nullable=False, index=True)
    purpose = db.Column(db.String(255), nullable=False)
    requested_duration_days = db.Column(db.Integer, nullable=False)
    emergency = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20), default="pending", index=True)  # pending/approved/denied/revoked
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    decision_at = db.Column(db.DateTime)
    approved_until = db.Column(db.DateTime)

    doctor = db.relationship("Doctor")
    patient = db.relationship("Patient")


# Routes

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        govt_id = request.form["govt_id"].strip()
        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        dob = datetime.strptime(request.form["dob"], "%Y-%m-%d").date()
        blood_group = request.form.get("blood_group")
        phone = request.form.get("phone", "").strip()

        if Patient.query.filter_by(email=email).first():
            flash("Email already registered", "danger")
            return redirect(url_for("register"))
        if Patient.query.filter_by(govt_id=govt_id).first():
            flash("Government ID already registered", "danger")
            return redirect(url_for("register"))

        snowflake_id = snowflake_generator.generate_id()
        hashed_password = generate_password_hash(password)
        new_patient = Patient(
            snowflake_id=snowflake_id,
            govt_id=govt_id,
            name=name,
            email=email,
            password=hashed_password,
            dob=dob,
            blood_group=blood_group,
            phone=phone,
        )
        db.session.add(new_patient)
        db.session.commit()
        flash(f"Registration successful! Your Patient ID: {snowflake_id}", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/doctor/register", methods=["GET", "POST"])
def doctor_register():
    if request.method == "POST":
        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        specialization = request.form.get("specialization", "").strip()
        license_number = request.form.get("license_number", "").strip()
        hospital = request.form.get("hospital", "").strip()
        phone = request.form.get("phone", "").strip()

        if Doctor.query.filter_by(email=email).first():
            flash("Email already registered", "danger")
            return redirect(url_for("doctor_register"))
        if license_number and Doctor.query.filter_by(license_number=license_number).first():
            flash("License number already registered", "danger")
            return redirect(url_for("doctor_register"))

        snowflake_id = snowflake_generator.generate_id()
        hashed_password = generate_password_hash(password)
        new_doctor = Doctor(
            snowflake_id=snowflake_id,
            name=name,
            email=email,
            password=hashed_password,
            specialization=specialization,
            license_number=license_number or None,
            hospital=hospital,
            phone=phone,
        )
        db.session.add(new_doctor)
        db.session.commit()
        flash(f"Doctor registration successful! ID: {snowflake_id}", "success")
        return redirect(url_for("doctor_login"))
    return render_template("doctor_register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        patient = Patient.query.filter_by(email=email).first()
        if patient and check_password_hash(patient.password, password):
            session.clear()
            session["user_id"] = patient.id
            session["user_name"] = patient.name
            session["user_type"] = "patient"
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid credentials", "danger")
    return render_template("login.html")

@app.route("/doctor/login", methods=["GET", "POST"])
def doctor_login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        doctor = Doctor.query.filter_by(email=email).first()
        if doctor and check_password_hash(doctor.password, password):
            session.clear()
            session["doctor_id"] = doctor.id
            session["doctor_name"] = doctor.name
            session["user_type"] = "doctor"
            
            session.setdefault("allowed_patient_ids", [])
            flash("Doctor login successful!", "success")
            return redirect(url_for("doctor_dashboard"))
        flash("Invalid credentials", "danger")
    return render_template("doctor_login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    patient = Patient.query.get(session["user_id"])
    records = (
        MedicalRecord.query.filter_by(patient_id=patient.id)
        .order_by(MedicalRecord.upload_date.desc())
        .all()
    )
    prescriptions = (
        Prescription.query.filter_by(patient_id=patient.id)
        .order_by(Prescription.prescription_date.desc())
        .all()
    )

    
    pending_count = Consent.query.filter(
        Consent.patient_id == patient.id,
        (Consent.status == "pending") | (Consent.status.is_(None))
    ).count()

    return render_template(
        "dashboard.html",
        patient=patient,
        records=records,
        prescriptions=prescriptions,
        consent_pending_count=pending_count,
    )


@app.route("/doctor/dashboard")
@doctor_required
def doctor_dashboard():
    doctor = Doctor.query.get(session["doctor_id"])
    return render_template("doctor_dashboard.html", doctor=doctor)


# Uploads (Patient)

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload_record():
    if request.method == "POST":
        file = request.files.get("file")
        record_type = request.form["record_type"].strip()
        title = request.form["title"].strip()
        description = request.form.get("description")
        test_date = datetime.strptime(request.form["test_date"], "%Y-%m-%d").date()

        if not file or not file.filename:
            flash("No file provided", "danger")
            return redirect(url_for("upload_record"))
        if not ext_ok(file.filename):
            flash("File type not allowed", "danger")
            return redirect(url_for("upload_record"))
        if not mime_ok(file, file.filename):
            flash("Suspicious file type", "danger")
            return redirect(url_for("upload_record"))

        file_content = file.read()
        file.seek(0)
        file_hash = hash_file_bytes(file_content)
        file_size = len(file_content)

        dedup_manager = DeduplicationManager(MedicalRecord)
        duplicate_check = dedup_manager.check_duplicate(file_hash, session["user_id"])
        if duplicate_check["is_duplicate"]:
            existing_record = duplicate_check["patient_duplicates"][0]
            flash(
                f"⚠️ Possible duplicate of '{existing_record.title}' from {existing_record.upload_date.strftime('%Y-%m-%d')}",
                "warning",
            )

        filename = secure_filename(file.filename)
        temp_filepath = os.path.join(
            app.config["UPLOAD_FOLDER"], f"temp_{session['user_id']}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
        )
        file.save(temp_filepath)

        encrypted_filename = f"encrypted_{snowflake_generator.generate_string_id()}_{filename}"
        encrypted_filepath = os.path.join(app.config["ENCRYPTED_FOLDER"], encrypted_filename)
        file_encryptor.encrypt_file(temp_filepath, encrypted_filepath)
        try:
            os.remove(temp_filepath)
        except OSError:
            pass

        record_snowflake_id = snowflake_generator.generate_id()
        new_record = MedicalRecord(
            snowflake_id=record_snowflake_id,
            patient_id=session["user_id"],
            record_type=record_type,
            title=title,
            description=description,
            filename=encrypted_filepath,
            file_hash=file_hash,
            file_size=file_size,
            is_encrypted=True,
            uploaded_by="Self",
            test_date=test_date,
        )
        db.session.add(new_record)
        db.session.commit()
        flash(f" Record uploaded successfully! ", "success")
        print(file_hash[:16])
        return redirect(url_for("dashboard"))
    return render_template("upload.html")


# Record Viewing/Downloading (Patient)

@app.route("/view-record/<int:record_id>")
@login_required
def view_record(record_id):
    record = MedicalRecord.query.get_or_404(record_id)
    if record.patient_id != session["user_id"]:
        flash("Unauthorized access", "danger")
        return redirect(url_for("dashboard"))
    log = AccessLog(
        patient_id=session["user_id"],
        accessed_by=session["user_name"],
        access_type="View",
        ip_address=request.remote_addr,
    )
    db.session.add(log)
    db.session.commit()
    return render_template("view_record.html", record=record)

@app.route("/download-record/<int:record_id>")
@login_required
def download_record(record_id):
    record = MedicalRecord.query.get_or_404(record_id)
    if record.patient_id != session["user_id"]:
        flash("Unauthorized access", "danger")
        return redirect(url_for("dashboard"))
    db.session.add(
        AccessLog(
            patient_id=session["user_id"],
            accessed_by=session["user_name"],
            access_type="Download",
            ip_address=request.remote_addr,
        )
    )
    db.session.commit()
    try:
        if record.is_encrypted:
            decrypted_data = file_encryptor.decrypt_file(record.filename)
            original_filename = record.filename.split("_", 2)[-1].replace("encrypted_files/", "")
            with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{original_filename}") as tmp:
                tmp.write(decrypted_data)
                path = tmp.name
            resp = send_file(path, as_attachment=True, download_name=original_filename)
            @resp.call_on_close
            def _cleanup():
                try:
                    os.unlink(path)
                except OSError:
                    pass
            return resp
        return send_file(record.filename, as_attachment=True)
    except Exception:
        flash("File not found or cannot be accessed", "danger")
        return redirect(url_for("dashboard"))


@app.route("/uploads/<path:filename>")
@login_required
def serve_file(filename):
    
    record = (
        MedicalRecord.query.filter(
            MedicalRecord.patient_id == session["user_id"],
            MedicalRecord.filename.like(f"%{secure_filename(filename)}%"),
        ).first()
    )
    if not record:
        flash("Unauthorized access", "danger")
        return redirect(url_for("dashboard"))
    try:
        if record.is_encrypted:
            data = file_encryptor.decrypt_file(record.filename)
            mime_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp.write(data)
                path = tmp.name
            resp = send_file(path, mimetype=mime_type)
            @resp.call_on_close
            def _cleanup():
                try:
                    os.unlink(path)
                except OSError:
                    pass
            return resp
        return send_file(record.filename)
    except Exception:
        flash("Error loading file", "danger")
        return redirect(url_for("dashboard"))

@app.route("/delete-record/<int:record_id>", methods=["POST"])
@login_required
def delete_record(record_id):
    record = MedicalRecord.query.get_or_404(record_id)
    if record.patient_id != session["user_id"]:
        flash("Unauthorized access", "danger")
        return redirect(url_for("dashboard"))
    try:
        if record.filename and os.path.exists(record.filename):
            os.remove(record.filename)
    except OSError:
        pass
    db.session.delete(record)
    db.session.commit()
    flash("Record deleted successfully", "success")
    return redirect(url_for("dashboard"))


# Prescriptions 

@app.route("/view-prescription/<int:prescription_id>")
@login_required
def view_prescription(prescription_id):
    prescription = Prescription.query.get_or_404(prescription_id)
    if prescription.patient_id != session["user_id"]:
        flash("Unauthorized access", "danger")
        return redirect(url_for("dashboard"))
    db.session.add(
        AccessLog(
            patient_id=session["user_id"],
            accessed_by=session["user_name"],
            access_type="View Prescription",
            ip_address=request.remote_addr,
        )
    )
    db.session.commit()
    return render_template("view_prescription.html", prescription=prescription)

@app.route("/search-patient", methods=["GET", "POST"])
@doctor_required
def search_patient():
    if request.method == "POST":
        term = request.form["search_term"].strip()
        q = Patient.query.filter(
            (Patient.govt_id.like(f"%{term}%"))
            | (Patient.name.like(f"%{term}%"))
            | (Patient.email.like(f"%{term}%"))
        )
        patients = q.all()
        return render_template("search_patient.html", patients=patients, searched=True)
    return render_template("search_patient.html", searched=False)

@app.route("/patient/<int:patient_id>")
@doctor_required
def view_patient(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    # Check consent 
    if not has_active_consent(patient_id, session["doctor_id"]):
        flash("Patient consent required to view records.", "warning")
        return redirect(url_for("doctor_request_consent", patient_id=patient_id))

    records = (
        MedicalRecord.query.filter_by(patient_id=patient_id)
        .order_by(MedicalRecord.upload_date.desc())
        .all()
    )
    prescriptions = (
        Prescription.query.filter_by(patient_id=patient_id)
        .order_by(Prescription.prescription_date.desc())
        .all()
    )
    db.session.add(
        AccessLog(
            patient_id=patient_id,
            accessed_by=session["doctor_name"],
            access_type="View",
            ip_address=request.remote_addr,
        )
    )
    db.session.commit()
    allowed = set(session.get("allowed_patient_ids", []))
    allowed.add(patient_id)
    session["allowed_patient_ids"] = list(allowed)
    return render_template("view_patient.html", patient=patient, records=records, prescriptions=prescriptions)

@app.route("/patient/<int:patient_id>/add-prescription", methods=["GET", "POST"])
@doctor_required
def add_prescription(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    doctor = Doctor.query.get(session["doctor_id"])  # current doctor
    if request.method == "POST":
        diagnosis = request.form["diagnosis"].strip()
        medications = request.form["medications"].strip()
        instructions = request.form.get("instructions", "").strip()
        prescription_date = datetime.strptime(request.form["prescription_date"], "%Y-%m-%d").date()
        prescription_snowflake_id = snowflake_generator.generate_id()
        new_rx = Prescription(
            snowflake_id=prescription_snowflake_id,
            patient_id=patient_id,
            doctor_name=session["doctor_name"],
            hospital=doctor.hospital,
            diagnosis=diagnosis,
            medications=medications,
            instructions=instructions,
            prescription_date=prescription_date,
        )
        db.session.add(new_rx)
        db.session.add(
            AccessLog(
                patient_id=patient_id,
                accessed_by=session["doctor_name"],
                access_type="Add Prescription",
                ip_address=request.remote_addr,
            )
        )
        db.session.commit()
        flash(f"Prescription added successfully! ", "success")
        print(prescription_snowflake_id)
        return redirect(url_for("view_patient", patient_id=patient_id))
    return render_template("add_prescription.html", patient=patient, doctor=doctor)

@app.route("/patient/<int:patient_id>/upload-record", methods=["GET", "POST"])
@doctor_required
def doctor_upload_record(patient_id):
    if patient_id not in set(session.get("allowed_patient_ids", [])):
        
        if not has_active_consent(patient_id, session["doctor_id"]):
            flash("Patient consent required before uploading records.", "warning")
            return redirect(url_for("doctor_request_consent", patient_id=patient_id))
        return redirect(url_for("view_patient", patient_id=patient_id))

    patient = Patient.query.get_or_404(patient_id)
    if request.method == "POST":
        file = request.files.get("file")
        record_type = request.form["record_type"].strip()
        title = request.form["title"].strip()
        description = request.form.get("description")
        test_date = datetime.strptime(request.form["test_date"], "%Y-%m-%d").date()

        if not file or not file.filename:
            flash("No file provided", "danger")
            return redirect(url_for("doctor_upload_record", patient_id=patient_id))
        if not ext_ok(file.filename) or not mime_ok(file, file.filename):
            flash("File type not allowed", "danger")
            return redirect(url_for("doctor_upload_record", patient_id=patient_id))

        file_content = file.read(); file.seek(0)
        file_hash = hash_file_bytes(file_content)
        file_size = len(file_content)

        dedup_manager = DeduplicationManager(MedicalRecord)
        duplicate_check = dedup_manager.check_duplicate(file_hash, patient_id)
        if duplicate_check.get("is_duplicate"):
            existing_record = duplicate_check["patient_duplicates"][0]
            flash(f"⚠️ Possible duplicate of '{existing_record.title}' from {existing_record.upload_date.strftime('%Y-%m-%d')}", "warning")

        filename = secure_filename(file.filename)
        temp_filepath = os.path.join(app.config["UPLOAD_FOLDER"], f"temp_{patient_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}")
        file.save(temp_filepath)

        encrypted_filename = f"encrypted_{snowflake_generator.generate_string_id()}_{filename}"
        encrypted_filepath = os.path.join(app.config["ENCRYPTED_FOLDER"], encrypted_filename)
        file_encryptor.encrypt_file(temp_filepath, encrypted_filepath)
        try: os.remove(temp_filepath)
        except OSError: pass

        record_snowflake_id = snowflake_generator.generate_id()
        new_record = MedicalRecord(
            snowflake_id=record_snowflake_id,
            patient_id=patient_id,
            record_type=record_type,
            title=title,
            description=description,
            filename=encrypted_filepath,
            file_hash=file_hash,
            file_size=file_size,
            is_encrypted=True,
            uploaded_by=f"Dr. {session['doctor_name']}",
            test_date=test_date,
        )
        db.session.add(new_record)
        db.session.add(AccessLog(patient_id=patient_id, accessed_by=session["doctor_name"], access_type="Upload Record", ip_address=request.remote_addr))
        db.session.commit()
        flash(f" Medical record uploaded successfully! ", "success")
        print(file_hash[:16])
        return redirect(url_for("view_patient", patient_id=patient_id))
    return render_template("doctor_upload_record.html", patient=patient, doctor=Doctor.query.get(session["doctor_id"]))

@app.route("/doctor/download-record/<int:record_id>")
@doctor_required
def doctor_download_record(record_id):
    record = MedicalRecord.query.get_or_404(record_id)
    
    if not has_active_consent(record.patient_id, session["doctor_id"]):
        flash("Patient consent required to download records.", "danger")
        return redirect(url_for("doctor_request_consent", patient_id=record.patient_id))

    db.session.add(AccessLog(patient_id=record.patient_id, accessed_by=session["doctor_name"], access_type="Download", ip_address=request.remote_addr))
    db.session.commit()
    try:
        if record.is_encrypted:
            data = file_encryptor.decrypt_file(record.filename)
            original_filename = record.filename.split("_", 2)[-1].replace("encrypted_files/", "")
            with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{original_filename}") as tmp:
                tmp.write(data)
                path = tmp.name
            resp = send_file(path, as_attachment=True, download_name=original_filename)
            @resp.call_on_close
            def _cleanup():
                try: os.unlink(path)
                except OSError: pass
            return resp
        return send_file(record.filename, as_attachment=True)
    except Exception:
        flash("File not found or cannot be accessed", "danger")
        return redirect(url_for("doctor_dashboard"))

    db.session.add(
        AccessLog(
            patient_id=record.patient_id,
            accessed_by=session["doctor_name"],
            access_type="Download",
            ip_address=request.remote_addr,
        )
    )
    db.session.commit()

    try:
        if record.is_encrypted:
            data = file_encryptor.decrypt_file(record.filename)
            original_filename = record.filename.split("_", 2)[-1].replace("encrypted_files/", "")
            with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{original_filename}") as tmp:
                tmp.write(data)
                path = tmp.name
            resp = send_file(path, as_attachment=True, download_name=original_filename)
            @resp.call_on_close
            def _cleanup():
                try:
                    os.unlink(path)
                except OSError:
                    pass
            return resp
        return send_file(record.filename, as_attachment=True)
    except Exception:
        flash("File not found or cannot be accessed", "danger")
        return redirect(url_for("doctor_dashboard"))


# Auth

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully", "info")
    return redirect(url_for("index"))

# Errors

@app.errorhandler(413)
def too_large(_):
    flash("File too large", "danger")
    return redirect(request.referrer or url_for("dashboard"))


# Consent request & management routes

@app.route("/doctor/patient/<int:patient_id>/request-consent", methods=["GET", "POST"])
@doctor_required
def doctor_request_consent(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    if request.method == "POST":
        purpose = request.form["purpose"].strip()
        duration_days = int(request.form.get("duration_days", 7))
        emergency = bool(request.form.get("emergency"))

        c = Consent(
            patient_id=patient_id,
            doctor_id=session["doctor_id"],
            purpose=purpose,
            requested_duration_days=duration_days,
            emergency=emergency,
            status="pending",
        )
        db.session.add(c)
        db.session.commit()
        flash("Consent request sent to patient.", "success")
        return redirect(url_for("doctor_dashboard"))
    
    recent = Consent.query.filter_by(patient_id=patient_id, doctor_id=session["doctor_id"]).order_by(Consent.created_at.desc()).limit(10).all()
    return render_template("doctor_request_consent.html", patient=patient, recent=recent)

@app.route("/patient/consents")
@login_required
def patient_consents():
    pid = session["user_id"]

    pending = (Consent.query
        .options(joinedload(Consent.doctor))
        .filter(Consent.patient_id == pid,
                (Consent.status == "pending") | (Consent.status.is_(None)))
        .order_by(Consent.created_at.desc())
        .all())

    active_rows = (Consent.query
        .options(joinedload(Consent.doctor))
        .filter_by(patient_id=pid, status="approved")
        .order_by(Consent.updated_at.desc())
        .all())
    active = [c for c in active_rows if c.approved_until and c.approved_until >= datetime.utcnow()]

    history = (Consent.query
        .options(joinedload(Consent.doctor))
        .filter(Consent.patient_id == pid, Consent.status.in_(["denied", "revoked"]))
        .order_by(Consent.updated_at.desc())
        .all())

    return render_template("patient_consents.html", pending=pending, active=active, history=history)


@app.route("/patient/consents/<int:consent_id>/approve", methods=["POST"]) 
@login_required
def approve_consent(consent_id):
    c = Consent.query.get_or_404(consent_id)
    if c.patient_id != session["user_id"]:
        abort(403)
    c.status = "approved"
    c.decision_at = datetime.utcnow()
    c.approved_until = datetime.utcnow() + timedelta(days=c.requested_duration_days)
    db.session.commit()
    flash("Consent approved.", "success")
    return redirect(url_for("patient_consents"))

@app.route("/patient/consents/<int:consent_id>/deny", methods=["POST"]) 
@login_required
def deny_consent(consent_id):
    c = Consent.query.get_or_404(consent_id)
    if c.patient_id != session["user_id"]:
        abort(403)
    c.status = "denied"
    c.decision_at = datetime.utcnow()
    db.session.commit()
    flash("Consent denied.", "info")
    return redirect(url_for("patient_consents"))

@app.context_processor
def inject_consent_pending_count():
    try:
        if session.get("user_id"):
            pid = session["user_id"]
            count = Consent.query.filter(
                Consent.patient_id == pid,
                (Consent.status == "pending") | (Consent.status.is_(None))
            ).count()
            return {"consent_pending_count": count}
    except Exception:
        pass
    return {"consent_pending_count": 0}


@app.route("/patient/consents/<int:consent_id>/revoke", methods=["POST"]) 
@login_required
def revoke_consent(consent_id):
    c = Consent.query.get_or_404(consent_id)
    if c.patient_id != session["user_id"]:
        abort(403)
    c.status = "revoked"
    c.decision_at = datetime.utcnow()
    db.session.commit()
    flash("Consent revoked.", "warning")
    return redirect(url_for("patient_consents"))



if __name__ == "__main__":
    with app.app_context():
        db.create_all()
     
    app.run(debug=os.getenv("FLASK_DEBUG", "0") == "1")
