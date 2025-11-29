import os
import secrets
from datetime import datetime, date

from dotenv import load_dotenv
from flask import (
    Flask, render_template, redirect, url_for,
    request, flash, jsonify, current_app
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import (
    StringField, PasswordField, TextAreaField,
    IntegerField, SelectField, FloatField, DateField, HiddenField
)
from wtforms.validators import DataRequired, Email, Length, Optional, NumberRange
from flask_login import (
    LoginManager, login_user, login_required, logout_user,
    current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash

from werkzeug.utils import secure_filename
from flask_wtf.file import FileField, FileAllowed   # put this near your other imports

from flask import send_from_directory


# allowed file types
ALLOWED_QUOTE_EXT = ["pdf", "png", "jpg", "jpeg"]

# Load environment from .env (useful locally; on Render use service env vars)
load_dotenv()


BASE_DIR = os.path.abspath(os.path.dirname(__file__))

STATUS_LIST = [
    "New",
    "Quoted",
    "Ordered",
    "Supplier Payment",
    "Shipped",
    "Delivered",
    "Payment",
]

STATUS_FLOW = [
    "New",
    "Quoted",
    "Ordered",
    "Supplier Payment",
    "Shipped",
    "Delivered",
    "Payment",
]

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", secrets.token_hex(16))
    # Use SQLite locally; override with DATABASE_URL (e.g., Postgres) in production
    # DATABASE_URL=postgresql://wsi_x2gu_user:kQweKESIUpuJjUenzxpeRIBLRDjkwrb4@dpg-d1p8k9idbo4c7386lmj0-a.frankfurt-postgres.render.com/wsi_x2gu

    #app.config["SQLALCHEMY_DATABASE_URI"] = postgresql://wsi_x2gu_user:kQweKESIUpuJjUenzxpeRIBLRDjkwrb4@dpg-d1p8k9idbo4c7386lmj0-a.frankfurt-postgres.render.com/wsi_x2gu
    
    # H A R D - C O D E D  (for local testing only)
    app.config["SQLALCHEMY_DATABASE_URI"] = (
        "postgresql+psycopg2://wsi_x2gu_user:"
        "kQweKESIUpuJjUenzxpeRIBLRDjkwrb4"
        "@dpg-d1p8k9idbo4c7386lmj0-a.frankfurt-postgres.render.com/"
        "wsi_x2gu?sslmode=require"
    )
    
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # ------------- PERSISTENT UPLOAD ROOT -------------
    # On Render, set DISK_ROOT=/var/data (the disk mount path)
    disk_root = os.getenv("DISK_ROOT", os.path.join(BASE_DIR, "static"))
    app.config["UPLOAD_DISK_ROOT"] = disk_root

    # Keep everything under a "quotes" subfolder on the disk
    quotes_dir = os.path.join(disk_root, "quotes")
    os.makedirs(quotes_dir, exist_ok=True)
    app.config["UPLOAD_FOLDER_QUOTES"] = quotes_dir

    return app


app = create_app()
db = SQLAlchemy(app)

# ---------- Auth setup ----------
login_manager = LoginManager(app)
login_manager.login_view = "login"




# ---------- Auth helpers ----------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])


# ---------- Forms ----------
class InquiryForm(FlaskForm):
    # Client inline fields (find-or-create)
    client_id = HiddenField("Client ID")
    client_name = StringField("Client Name", validators=[DataRequired(), Length(max=120)])
    client_phone = StringField("Client Phone", validators=[Optional(), Length(max=50)])
    client_email = StringField("Client Email", validators=[Optional(), Email()])
    client_company = StringField("Company", validators=[Optional(), Length(max=120)])

    # Inquiry fields
    title = StringField("Inquiry Title", validators=[DataRequired(), Length(max=160)])
    description = TextAreaField("Description", validators=[Optional()])
    priority = SelectField(
        "Priority",
        choices=[("Low", "Low"), ("Normal", "Normal"), ("High", "High"), ("Urgent", "Urgent")],
        default="Normal",
    )
    budget = FloatField("Budget", validators=[Optional(), NumberRange(min=0)])
    currency = SelectField(
        "Currency",
        choices=[("MZN", "MZN"), ("ZAR", "ZAR"), ("EUR", "EUR"), ("USD", "USD")],
        default="MZN",
    )
    expected_delivery = DateField("Expected Delivery", validators=[Optional()])


class ItemForm(FlaskForm):
    product_name = StringField("Product", validators=[DataRequired(), Length(max=200)])
    qty = IntegerField("Qty", validators=[DataRequired(), NumberRange(min=1)])
    unit = StringField("Unit", default="pcs", validators=[Optional(), Length(max=40)])


class StatusForm(FlaskForm):
    status = SelectField(
        "Status",
        choices=[(s, s) for s in STATUS_FLOW],
        default="New"
    )
    note = TextAreaField("Note", validators=[Optional()])

    # new: 3 quotes + which one is selected
    quote1 = FileField("Quote 1", validators=[Optional(), FileAllowed(ALLOWED_QUOTE_EXT)])
    quote2 = FileField("Quote 2", validators=[Optional(), FileAllowed(ALLOWED_QUOTE_EXT)])
    quote3 = FileField("Quote 3", validators=[Optional(), FileAllowed(ALLOWED_QUOTE_EXT)])
    selected_quote = SelectField(
        "Selected",
        choices=[("1", "Quote 1"), ("2", "Quote 2"), ("3", "Quote 3")],
        validators=[Optional()]
    )

    # NEW — PO upload
    po_file = FileField("Client PO", validators=[Optional(), FileAllowed(ALLOWED_QUOTE_EXT)])

    proof_of_delivery = FileField("Proof of Delivery", validators=[Optional(), FileAllowed(ALLOWED_QUOTE_EXT)])

    proof_of_delivery = FileField(
    "Proof of Delivery",
    validators=[Optional(), FileAllowed(ALLOWED_QUOTE_EXT)]
)

def configure_status_choices(form, current_status: str | None):
    """
    Limita as opções de status para o estado atual e os seguintes,
    evitando que o utilizador volte para estados anteriores.
    """
    if not current_status:
        form.status.choices = [(s, s) for s in STATUS_FLOW]
        return

    try:
        idx = STATUS_FLOW.index(current_status)
    except ValueError:
        # se por algum motivo o estado não estiver na lista, mostra tudo
        form.status.choices = [(s, s) for s in STATUS_FLOW]
    else:
        allowed = STATUS_FLOW[idx:]   # atual + próximos
        form.status.choices = [(s, s) for s in allowed]



# ---------- Models (all with _afrigrown postfix) ----------
class User(UserMixin, db.Model):
    __tablename__ = "users_afrigrown"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False, default="User")
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    # NEW: events done by this user
    status_events = db.relationship("StatusEvent", back_populates="actor", lazy=True)

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)


class Client(db.Model):
    __tablename__ = "clients_afrigrown"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    company = db.Column(db.String(120))
    email = db.Column(db.String(255))
    phone = db.Column(db.String(50))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # relationships
    inquiries = db.relationship("Inquiry", back_populates="client", lazy=True)


class Inquiry(db.Model):
    __tablename__ = "inquiries_afrigrown"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(160), nullable=False)
    description = db.Column(db.Text)
    priority = db.Column(db.String(20), default="Normal")   # Low, Normal, High, Urgent
    status = db.Column(db.String(30), default="New")        # New, Quoted, Ordered, Shipped, Delivered, Closed, Lost
    budget = db.Column(db.Float)
    currency = db.Column(db.String(12), default="MZN")
    expected_delivery = db.Column(db.Date)

    client_id = db.Column(db.Integer, db.ForeignKey("clients_afrigrown.id"), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey("users_afrigrown.id"))

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)



    # relationships
    client = db.relationship("Client", back_populates="inquiries")
    items = db.relationship("InquiryItem", back_populates="inquiry", cascade="all, delete-orphan", lazy=True)
    events = db.relationship("StatusEvent", back_populates="inquiry", cascade="all, delete-orphan", lazy=True)

    quotes = db.relationship("QuoteOption", backref="inquiry",cascade="all, delete-orphan", lazy=True)

    # at top of Inquiry model
    #po_files = db.relationship("PurchaseOrder", backref="inquiry", cascade="all, delete-orphan", lazy=True)

    # 🔴 FIXED: use back_populates instead of backref
    po_files = db.relationship("PurchaseOrder", back_populates="inquiry",
                               cascade="all, delete-orphan", lazy=True)
    
    # NEW: Proof of Delivery files
    pods = db.relationship("ProofOfDelivery", back_populates="inquiry",
                           cascade="all, delete-orphan", lazy=True)



class InquiryItem(db.Model):
    __tablename__ = "inquiry_items_afrigrown"

    id = db.Column(db.Integer, primary_key=True)
    inquiry_id = db.Column(db.Integer, db.ForeignKey("inquiries_afrigrown.id"), nullable=False)
    product_name = db.Column(db.String(200), nullable=False)
    qty = db.Column(db.Integer, default=1)
    unit = db.Column(db.String(40), default="pcs")

    inquiry = db.relationship("Inquiry", back_populates="items")


class StatusEvent(db.Model):
    __tablename__ = "status_events_afrigrown"

    id = db.Column(db.Integer, primary_key=True)
    inquiry_id = db.Column(db.Integer, db.ForeignKey("inquiries_afrigrown.id"), nullable=False)
    status = db.Column(db.String(30), nullable=False)
    note = db.Column(db.Text)
    created_by = db.Column(db.Integer, db.ForeignKey("users_afrigrown.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    inquiry = db.relationship("Inquiry", back_populates="events")

    # NEW: who acted
    actor = db.relationship("User", back_populates="status_events")


class QuoteOption(db.Model):
    __tablename__ = "quote_options_afrigrown"

    id = db.Column(db.Integer, primary_key=True)
    inquiry_id = db.Column(db.Integer, db.ForeignKey("inquiries_afrigrown.id"), nullable=False)
    label = db.Column(db.String(20))          # e.g. "Quote 1"
    file_name = db.Column(db.String(255))
    file_path = db.Column(db.String(255))     # relative path under static/...
    is_selected = db.Column(db.Boolean, default=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey("users_afrigrown.id"))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)


class PurchaseOrder(db.Model):
    __tablename__ = "purchase_orders_afrigrown"

    id = db.Column(db.Integer, primary_key=True)
    inquiry_id = db.Column(db.Integer, db.ForeignKey("inquiries_afrigrown.id"), nullable=False)
    file_name = db.Column(db.String(255))
    file_path = db.Column(db.String(255))
    uploaded_by = db.Column(db.Integer, db.ForeignKey("users_afrigrown.id"))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

    #inquiry = db.relationship("Inquiry", backref="po_files")

    # 🔴 FIXED: match back_populates, no backref here
    inquiry = db.relationship("Inquiry", back_populates="po_files")


class ProofOfDelivery(db.Model):
    __tablename__ = "proof_of_delivery_afrigrown"

    id = db.Column(db.Integer, primary_key=True)
    inquiry_id = db.Column(db.Integer, db.ForeignKey("inquiries_afrigrown.id"), nullable=False)
    file_name = db.Column(db.String(255))
    file_path = db.Column(db.String(255))
    uploaded_by = db.Column(db.Integer, db.ForeignKey("users_afrigrown.id"))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

    inquiry = db.relationship("Inquiry", back_populates="pods")


# ---------- Routes ----------
#@app.route("/")
#@login_required
#def index():
    # Quick stats for dashboard
#    stats = {
#        "total": Inquiry.query.count(),
#        "new": Inquiry.query.filter_by(status="New").count(),
#        "quoted": Inquiry.query.filter_by(status="Quoted").count(),
#        "shipped": Inquiry.query.filter_by(status="Shipped").count(),
#    }
#    recent = Inquiry.query.order_by(Inquiry.updated_at.desc()).limit(10).all()
#    return render_template("index.html", stats=stats, recent=recent)

@app.route("/")
@login_required
def index():
    # Quick stats for dashboard
    stats = {
        "total": Inquiry.query.count()
    }

    # counts for each status in STATUS_LIST
    for s in STATUS_LIST:
        stats[s] = Inquiry.query.filter_by(status=s).count()

    recent = Inquiry.query.order_by(Inquiry.updated_at.desc()).limit(10).all()
    return render_template("index.html",
                           stats=stats,
                           recent=recent,
                           statuses=STATUS_LIST)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for("index"))
        flash("Invalid credentials", "danger")
    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/inquiries/new", methods=["GET", "POST"])
@login_required
def new_inquiry():
    form = InquiryForm()
    if form.validate_on_submit():
        # Find or create client
        client = None
        if form.client_id.data:
            client = Client.query.get(int(form.client_id.data))
        if not client:
            client = Client(
                name=form.client_name.data.strip(),
                company=(form.client_company.data or "").strip() or None,
                email=(form.client_email.data or "").strip() or None,
                phone=(form.client_phone.data or "").strip() or None,
            )
            db.session.add(client)
            db.session.flush()

        inquiry = Inquiry(
            title=form.title.data.strip(),
            description=form.description.data,
            priority=form.priority.data,
            budget=form.budget.data if form.budget.data is not None else None,
            currency=form.currency.data,
            expected_delivery=form.expected_delivery.data if form.expected_delivery.data else None,
            client_id=client.id,
            created_by=current_user.id if current_user.is_authenticated else None,
        )
        db.session.add(inquiry)
        db.session.flush()
        db.session.add(StatusEvent(inquiry_id=inquiry.id, status="New", note="Created", created_by=current_user.id))
        db.session.commit()

        flash("Inquiry created", "success")
        return redirect(url_for("inquiry_detail", inquiry_id=inquiry.id))

    return render_template("inquiry_form.html", form=form, mode="new")


@app.route("/inquiries/<int:inquiry_id>")
@login_required
def inquiry_detail(inquiry_id):
    inq = Inquiry.query.get_or_404(inquiry_id)
    item_form = ItemForm()
    status_form = StatusForm()

#    return render_template("inquiry_detail.html", inq=inq, item_form=item_form, status_form=status_form)

    # 🔹 limitar opções de status conforme o estado atual
    configure_status_choices(status_form, inq.status)
    status_form.status.data = inq.status  # selecionar o estado atual por defeito

    return render_template(
        "inquiry_detail.html",
        inq=inq,
        item_form=item_form,
        status_form=status_form
    )


@app.route("/inquiries/<int:inquiry_id>/add_item", methods=["POST"])
@login_required
def add_item(inquiry_id):
    inq = Inquiry.query.get_or_404(inquiry_id)
    form = ItemForm()
    if form.validate_on_submit():
        item = InquiryItem(
            inquiry_id=inq.id,
            product_name=form.product_name.data.strip(),
            qty=form.qty.data,
            unit=form.unit.data or "pcs",
        )
        db.session.add(item)
        db.session.commit()
        flash("Item added", "success")
    else:
        flash("Invalid item", "danger")
    return redirect(url_for("inquiry_detail", inquiry_id=inq.id))


@app.route("/inquiries/<int:inquiry_id>/status", methods=["POST"])
@login_required
def update_status(inquiry_id):
    inq = Inquiry.query.get_or_404(inquiry_id)
    form = StatusForm()

    #if not form.validate_on_submit():
    #    flash("Invalid status", "danger")
    #    return redirect(url_for("inquiry_detail", inquiry_id=inq.id))

    #new_status = form.status.data

    # 🔹 MESMA configuração de choices, para o POST ser válido
    configure_status_choices(form, inq.status)

    if not form.validate_on_submit():
        flash("Invalid status", "danger")
        return redirect(url_for("inquiry_detail", inquiry_id=inq.id))

    new_status = form.status.data

    # If moving to Quoted and no quotes yet, require 3 uploads
    if new_status == "Quoted" and len(inq.quotes) == 0:
        files = [form.quote1.data, form.quote2.data, form.quote3.data]
        if not all(files):
            flash("You must upload 3 quote files before setting status to Quoted.", "danger")
            return redirect(url_for("inquiry_detail", inquiry_id=inq.id))

        if not form.selected_quote.data:
            flash("Please select which quote was approved.", "danger")
            return redirect(url_for("inquiry_detail", inquiry_id=inq.id))

        upload_dir = current_app.config["UPLOAD_FOLDER_QUOTES"]
        selected_index = int(form.selected_quote.data)

        # save each file
        for idx, f in enumerate(files, start=1):
            if not f:
                continue
            filename = secure_filename(f.filename)
            # make it unique
            final_name = f"inq{inq.id}_q{idx}_{int(datetime.utcnow().timestamp())}_{filename}"
            save_path = os.path.join(upload_dir, final_name)
            f.save(save_path)

            rel_path = f"quotes/{final_name}"  # <<< IMPORTANT CHANGE
            opt = QuoteOption(
                inquiry_id=inq.id,
                label=f"Quote {idx}",
                file_name=filename,
                file_path=rel_path,
                is_selected=(idx == selected_index),
                uploaded_by=current_user.id
            )
            db.session.add(opt)

    # If moving to "Ordered", require a PO file
    if new_status == "Ordered":
        if not form.po_file.data:
            flash("You must upload a Client PO before moving to 'Ordered'.", "danger")
            return redirect(url_for('inquiry_detail', inquiry_id=inq.id))

        # save PO file
        f = form.po_file.data
        filename = secure_filename(f.filename)
        final_name = f"inq{inq.id}_PO_{int(datetime.utcnow().timestamp())}_{filename}"

        upload_dir = current_app.config["UPLOAD_FOLDER_QUOTES"]  # same folder for now
        save_path = os.path.join(upload_dir, final_name)
        f.save(save_path)

        rel_path = f"quotes/{final_name}"  # static URL path

        po = PurchaseOrder(
            inquiry_id=inq.id,
            file_name=filename,
            file_path=rel_path,
            uploaded_by=current_user.id
        )
        db.session.add(po)


    # only force POD if there is no POD yet
    if new_status == "Delivered" and len(getattr(inq, "pods", [])) == 0:
        f = form.proof_of_delivery.data

        # f can be None or have empty filename if user didn't pick a file
        if not f or f.filename == "":
            flash("You must upload a Proof of Delivery before marking as Delivered.", "danger")
            return redirect(url_for("inquiry_detail", inquiry_id=inq.id))

        filename = secure_filename(f.filename)
        final_name = f"inq{inq.id}_POD_{int(datetime.utcnow().timestamp())}_{filename}"

        upload_dir = current_app.config["UPLOAD_FOLDER_QUOTES"]
        save_path = os.path.join(upload_dir, final_name)
        f.save(save_path)

        rel_path = f"quotes/{final_name}"

        pod = ProofOfDelivery(
            inquiry_id=inq.id,
            file_name=filename,
            file_path=rel_path,
            uploaded_by=current_user.id,
        )
        db.session.add(pod)

    # update status + history event
    inq.status = new_status
    db.session.add(StatusEvent(
        inquiry_id=inq.id,
        status=new_status,
        note=form.note.data,
        created_by=current_user.id
    ))
    db.session.commit()
    flash("Status updated", "success")
    return redirect(url_for("inquiry_detail", inquiry_id=inq.id))


@app.route("/clients/search")
@login_required
def client_search():
    """Simple AJAX search by name/phone/email"""
    q = request.args.get("q", "").strip()
    res = []
    if q:
        like = f"%{q}%"
        clients = Client.query.filter(
            db.or_(
                Client.name.ilike(like),
                Client.phone.ilike(like),
                Client.email.ilike(like),
            )
        ).limit(20).all()
        for c in clients:
            res.append({
                "id": c.id,
                "name": c.name,
                "company": c.company or "",
                "email": c.email or "",
                "phone": c.phone or ""
            })
    return jsonify(res)


# ---------- Simple token API for integrations (e.g., n8n/UltraMsg) ----------
@app.route("/api/inquiries", methods=["POST"])
def api_create_inquiry():
    token = request.headers.get("X-API-KEY", "")
    # For demo: use SECRET_KEY as token. In production, store/manage tokens properly.
    if token != app.config["SECRET_KEY"]:
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(force=True, silent=True) or {}
    client_name = data.get("client_name")
    title = data.get("title")
    if not client_name or not title:
        return jsonify({"error": "client_name and title are required"}), 400

    client = Client(
        name=client_name,
        company=data.get("client_company"),
        email=data.get("client_email"),
        phone=data.get("client_phone"),
    )
    db.session.add(client)
    db.session.flush()

    inq = Inquiry(
        title=title,
        description=data.get("description"),
        priority=data.get("priority", "Normal"),
        budget=data.get("budget"),
        currency=data.get("currency", "MZN"),
        expected_delivery=None,
        client_id=client.id,
    )
    db.session.add(inq)
    db.session.flush()

    db.session.add(StatusEvent(inquiry_id=inq.id, status="New", note="Created via API"))

    for it in data.get("items", []):
        db.session.add(InquiryItem(
            inquiry_id=inq.id,
            product_name=it.get("product_name", "Item"),
            qty=int(it.get("qty", 1)),
            unit=it.get("unit", "pcs"),
        ))

    db.session.commit()
    return jsonify({"id": inq.id, "status": "created"}), 201


@app.route("/inquiries")
@login_required
def inquiry_list():
    status = request.args.get("status")  # e.g. "Delivered"

    q = Inquiry.query.order_by(Inquiry.updated_at.desc())
    title = "All Inquiries"

    if status:
        q = q.filter_by(status=status)
        title = f"{status} Inquiries"

    inquiries = q.all()

    return render_template(
        "inquiry_list.html",
        inquiries=inquiries,
        status=status,
        title=title,
    )


@app.route("/uploads/<path:filename>")
@login_required
def uploaded_file(filename):
    """Serve uploaded files (quotes, POs, PODs) from the persistent disk."""
    root = current_app.config["UPLOAD_DISK_ROOT"]
    return send_from_directory(root, filename)



# ---------- CLI Helper ----------
@app.cli.command("init-db")
def init_db():
    """Initialize tables and seed admin from env vars."""
    db.create_all()
    admin_email = os.getenv("ADMIN_EMAIL", "admin@example.com").lower()
    admin_pw = os.getenv("ADMIN_PASSWORD", "admin123")

    if not User.query.filter_by(email=admin_email).first():
        u = User(email=admin_email, name="Admin", is_admin=True)
        u.set_password(admin_pw)
        db.session.add(u)
        db.session.commit()
        print(f"Admin created: {admin_email} / {admin_pw}")
    else:
        print("Admin already exists")


from datetime import datetime

@app.context_processor
def inject_globals():
    # allows {{ now().year }} in any template
    return {
        "now": datetime.now,   # or datetime.utcnow if you prefer UTC
        "brand": "AfriGrown",  # optional helper you can use in templates
    }


@app.cli.command("create-user")
def create_user():
    """Interactive: create a user quickly."""
    import getpass
    email = input("Email: ").strip().lower()
    name = input("Name: ").strip() or "User"
    is_admin = (input("Is admin? [y/N]: ").strip().lower() == "y")
    pw = getpass.getpass("Password: ").strip()

    if not email or not pw:
        print("Email and password are required.")
        return

    if User.query.filter_by(email=email).first():
        print("User already exists.")
        return

    u = User(email=email, name=name, is_admin=is_admin)
    u.set_password(pw)
    db.session.add(u)
    db.session.commit()
    print(f"User created: {email} (admin={is_admin})")


@app.cli.command("seed-demo")
def seed_demo():
    """Create a couple of clients and inquiries for testing."""
    # Clients
    c1 = Client(name="Nilza & David", company="Voyage Interiores", email="nilza@example.com", phone="+25884...")
    c2 = Client(name="Indico Seguros", company="Indico", email="ops@indico.mz", phone="+25882...")
    db.session.add_all([c1, c2]); db.session.flush()

    # Inquiries
    i1 = Inquiry(title="Zennio Z70 panels", description="6 panels for floor controllers",
                 priority="High", status="New", currency="MZN", client_id=c1.id)
    i2 = Inquiry(title="Presence sensors (KNX)", description="20 ceiling sensors",
                 priority="Normal", status="Quoted", currency="MZN", client_id=c2.id)
    db.session.add_all([i1, i2]); db.session.flush()

    db.session.add_all([
        InquiryItem(inquiry_id=i1.id, product_name="Z70 Panel", qty=6, unit="pcs"),
        InquiryItem(inquiry_id=i2.id, product_name="Presence Sensor", qty=20, unit="pcs"),
        StatusEvent(inquiry_id=i1.id, status="New", note="Initial creation"),
        StatusEvent(inquiry_id=i2.id, status="Quoted", note="Quote sent"),
    ])

    db.session.commit()
    print("Demo data seeded.")



# ---------- Dev entry ----------
if __name__ == "__main__":
    with app.app_context():
        #init_db()
        db.create_all()
    
    # For production on Render, use gunicorn: `gunicorn app:app`
    app.run(debug=True, host="0.0.0.0", port=5000)
