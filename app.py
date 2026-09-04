import os
import hmac
import secrets
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, session, flash, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
from werkzeug.utils import secure_filename

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///nagarsetu.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 25 * 1024 * 1024
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', '').lower() == 'true'

UPLOAD_FOLDER = os.path.join(app.root_path, 'uploads', 'complaints')
LEGACY_UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads', 'complaints')
ALLOWED_IMAGE_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'webp'}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# ----------------------------
# Models
# ----------------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='citizen')
    phone = db.Column(db.String(30), default='')

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Department(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(20), unique=True, nullable=False)
    description = db.Column(db.Text, default='')

class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(30), default='submitted')
    priority = db.Column(db.String(20), default='medium')
    location = db.Column(db.String(200), default='')
    citizen_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'), nullable=True)
    officer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime, nullable=True)

    citizen = db.relationship('User', foreign_keys=[citizen_id])
    officer = db.relationship('User', foreign_keys=[officer_id])
    department = db.relationship('Department')
    photos = db.relationship('ComplaintPhoto', backref='complaint', lazy=True, cascade='all, delete-orphan')
    comments = db.relationship('ComplaintComment', backref='complaint', lazy=True, cascade='all, delete-orphan')

    def timeline(self):
        return [
            {'status': self.status, 'message': f'Current status: {self.status}', 'timestamp': self.created_at}
        ]

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(150), nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User')

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    complaint_id = db.Column(db.Integer, db.ForeignKey('complaint.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ComplaintPhoto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    complaint_id = db.Column(db.Integer, db.ForeignKey('complaint.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ComplaintComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    complaint_id = db.Column(db.Integer, db.ForeignKey('complaint.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User')

# ----------------------------
# Helpers
# ----------------------------

def login_required(role=None):
    def wrapper(fn):
        def decorated(*args, **kwargs):
            user_id = session.get('user_id')
            if not user_id:
                flash('Please login first.', 'danger')
                return redirect(url_for('login'))
            user = db.session.get(User, user_id)
            if not user:
                session.clear()
                flash('User session invalid.', 'danger')
                return redirect(url_for('login'))
            if role and user.role != role:
                flash('Access denied.', 'danger')
                return redirect(url_for('dashboard'))
            return fn(user, *args, **kwargs)
        decorated.__name__ = fn.__name__
        return decorated
    return wrapper


def get_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    return session['csrf_token']


@app.before_request
def csrf_protect():
    if request.method == 'POST':
        submitted_token = request.form.get('_csrf_token', '')
        expected_token = session.get('csrf_token', '')
        if not expected_token or not hmac.compare_digest(submitted_token, expected_token):
            abort(400, description='Invalid or missing form security token.')


def create_notification(user_id, title, message):
    notif = Notification(user_id=user_id, title=title, message=message)
    db.session.add(notif)
    db.session.commit()


def allowed_image(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS


def valid_password(password):
    return len(password) >= 8 and any(character.isalpha() for character in password) and any(character.isdigit() for character in password)


def save_complaint_photos(files, complaint_id):
    selected_files = [image for image in files if image and image.filename]
    for image in selected_files:
        if not allowed_image(image.filename):
            raise ValueError('Only JPG, PNG, GIF, and WEBP image files are allowed.')
        if not secure_filename(image.filename):
            raise ValueError('One of the uploaded image names is invalid.')

    photos = []
    for image in selected_files:
        filename = secure_filename(image.filename)
        unique_name = f'{complaint_id}_{datetime.utcnow().strftime("%Y%m%d%H%M%S%f")}_{filename}'
        image.save(os.path.join(UPLOAD_FOLDER, unique_name))
        photos.append(ComplaintPhoto(complaint_id=complaint_id, filename=unique_name))
    return photos


def create_seed_data():
    if User.query.first():
        return

    admin = User(name='Admin User', email='admin@nagarsetu.com', role='admin', phone='9999999999')
    admin.set_password('admin123')
    officer = User(name='Officer User', email='officer@nagarsetu.com', role='officer', phone='8888888888')
    officer.set_password('officer123')
    citizen = User(name='Citizen User', email='citizen@nagarsetu.com', role='citizen', phone='7777777777')
    citizen.set_password('citizen123')

    dept1 = Department(name='Public Works', code='PW', description='Roads, drains, and infrastructure issues')
    dept2 = Department(name='Water Department', code='WD', description='Water supply and leakage issues')
    dept3 = Department(name='Electricity Department', code='ED', description='Street lights and power failures')

    db.session.add_all([admin, officer, citizen, dept1, dept2, dept3])
    db.session.commit()

    complaint = Complaint(
        title='Pothole on Main Road',
        description='Large pothole near school gate causing traffic issues.',
        category='Pothole',
        status='verified',
        priority='high',
        location='Main Road, City Center',
        citizen_id=citizen.id,
        department_id=dept1.id,
        officer_id=officer.id
    )
    db.session.add(complaint)
    db.session.commit()

    create_notification(citizen.id, 'Complaint Verified', 'Your complaint has been verified by the admin.')
    create_notification(officer.id, 'New Complaint Assigned', 'A new complaint has been assigned to you.')

# ----------------------------
# Routes
# ----------------------------

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        phone = request.form.get('phone', '').strip()

        if not name or not email or not password:
            flash('Please fill all required fields.', 'danger')
            return render_template('register.html')

        if not valid_password(password):
            flash('Password must be at least 8 characters and contain a letter and a number.', 'danger')
            return render_template('register.html')

        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return render_template('register.html')

        user = User(name=name, email=email, phone=phone, role='citizen')
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Registration successful. Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/admin/users/new', methods=['GET', 'POST'])
@login_required('admin')
def create_staff_user(user):
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        phone = request.form.get('phone', '').strip()
        role = request.form.get('role', '').strip().lower()

        if not name or not email or not password or role not in {'admin', 'officer'}:
            flash('Name, email, password, and a valid staff role are required.', 'danger')
            return render_template('create_staff_user.html')
        if not valid_password(password):
            flash('Password must be at least 8 characters and contain a letter and a number.', 'danger')
            return render_template('create_staff_user.html')
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return render_template('create_staff_user.html')

        staff_user = User(name=name, email=email, phone=phone, role=role)
        staff_user.set_password(password)
        db.session.add(staff_user)
        db.session.commit()
        flash(f'{role.title()} account created successfully.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('create_staff_user.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['role'] = user.role
            flash('Login successful.', 'success')
            return redirect(url_for('dashboard'))

        flash('Invalid email or password.', 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = db.session.get(User, session['user_id'])
    if not user:
        return redirect(url_for('login'))

    if user.role == 'admin':
        complaints = Complaint.query.filter(Complaint.status != 'closed').order_by(Complaint.created_at.desc()).all()
        closed_complaints = Complaint.query.filter_by(status='closed').order_by(Complaint.created_at.desc()).all()
        officers = User.query.filter_by(role='officer').all()
        departments = Department.query.all()
        return render_template('admin_dashboard.html', user=user, complaints=complaints, closed_complaints=closed_complaints, officers=officers, departments=departments)

    if user.role == 'officer':
        complaints = Complaint.query.filter(Complaint.officer_id == user.id, Complaint.status != 'closed').order_by(Complaint.created_at.desc()).all()
        closed_complaints = Complaint.query.filter_by(officer_id=user.id, status='closed').order_by(Complaint.created_at.desc()).all()
        return render_template('officer_dashboard.html', user=user, complaints=complaints, closed_complaints=closed_complaints)

    complaints = Complaint.query.filter(Complaint.citizen_id == user.id, Complaint.status != 'closed').order_by(Complaint.created_at.desc()).all()
    closed_complaints = Complaint.query.filter_by(citizen_id=user.id, status='closed').order_by(Complaint.created_at.desc()).all()
    return render_template('citizen_dashboard.html', user=user, complaints=complaints, closed_complaints=closed_complaints)


@app.route('/complaint/new', methods=['GET', 'POST'])
@login_required('citizen')
def new_complaint(user):
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        category = request.form.get('category', '').strip()
        priority = request.form.get('priority', 'medium')
        location = request.form.get('location', '').strip()

        images = request.files.getlist('photos')
        if not title or not description or not category:
            flash('Please complete complaint details.', 'danger')
            return render_template('new_complaint.html')
        if len(title) > 200 or len(category) > 50 or len(location) > 200 or len(description) > 10000:
            flash('Complaint details exceed the allowed length.', 'danger')
            return render_template('new_complaint.html')
        if priority not in {'low', 'medium', 'high'}:
            flash('Please select a valid priority.', 'danger')
            return render_template('new_complaint.html')
        if len([image for image in images if image and image.filename]) > 5:
            flash('You can upload a maximum of 5 photos.', 'danger')
            return render_template('new_complaint.html')

        complaint = Complaint(
            title=title,
            description=description,
            category=category,
            priority=priority,
            location=location,
            citizen_id=user.id,
            status='submitted'
        )
        try:
            db.session.add(complaint)
            db.session.flush()
            db.session.add_all(save_complaint_photos(images, complaint.id))
            db.session.commit()
        except ValueError as error:
            db.session.rollback()
            flash(str(error), 'danger')
            return render_template('new_complaint.html')

        flash('Complaint submitted successfully.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('new_complaint.html')


@app.route('/complaint/<int:complaint_id>', methods=['GET', 'POST'])
@login_required()
def complaint_detail(user, complaint_id):
    complaint = Complaint.query.get_or_404(complaint_id)
    can_view = user.role == 'admin' or complaint.citizen_id == user.id or complaint.officer_id == user.id
    if not can_view:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    officers = User.query.filter_by(role='officer').all()
    departments = Department.query.all()

    if request.method == 'POST':
        action = request.form.get('action')

        if user.role == 'admin' and action == 'verify':
            if complaint.status != 'submitted':
                flash('Only submitted complaints can be verified.', 'warning')
                return redirect(url_for('complaint_detail', complaint_id=complaint.id))
            complaint.status = 'verified'
            db.session.commit()
            create_notification(complaint.citizen_id, 'Complaint Verified', f'Your complaint "{complaint.title}" has been verified.')
            flash('Complaint verified.', 'success')
            return redirect(url_for('dashboard'))

        if user.role == 'admin' and action == 'assign':
            officer_id = request.form.get('officer_id', type=int)
            department_id = request.form.get('department_id', type=int)
            officer = User.query.filter_by(id=officer_id, role='officer').first() if officer_id else None
            department = db.session.get(Department, department_id) if department_id else None
            if officer and complaint.status != 'closed':
                complaint.officer_id = officer_id
                complaint.department_id = department.id if department else None
                complaint.status = 'assigned'
                db.session.commit()
                create_notification(complaint.citizen_id, 'Complaint Assigned', f'Your complaint "{complaint.title}" has been assigned to an officer.')
                create_notification(officer_id, 'New Complaint Assigned', f'You have been assigned complaint: {complaint.title}')
                flash('Complaint assigned to officer.', 'success')
            else:
                flash('Please select a valid officer and an active complaint.', 'danger')
            return redirect(url_for('complaint_detail', complaint_id=complaint.id))

        if user.role == 'officer' and action == 'start_work':
            if complaint.officer_id != user.id or complaint.status not in {'assigned', 'verified'}:
                flash('This complaint is not available to start.', 'warning')
                return redirect(url_for('complaint_detail', complaint_id=complaint.id))
            complaint.status = 'in_progress'
            db.session.commit()
            create_notification(complaint.citizen_id, 'Work Started', f'Work has started on your complaint "{complaint.title}".')
            flash('Work started on complaint.', 'success')
            return redirect(url_for('dashboard'))

        if user.role == 'officer' and action == 'resolve':
            if complaint.officer_id != user.id or complaint.status != 'in_progress':
                flash('Only an in-progress complaint assigned to you can be resolved.', 'warning')
                return redirect(url_for('complaint_detail', complaint_id=complaint.id))
            comment = request.form.get('resolution_comment', '').strip()
            if not comment:
                flash('A resolution comment is required before marking the complaint resolved.', 'danger')
                return redirect(url_for('complaint_detail', complaint_id=complaint.id))
            db.session.add(ComplaintComment(complaint_id=complaint.id, user_id=user.id, text=comment))
            complaint.status = 'resolved'
            complaint.resolved_at = datetime.utcnow()
            db.session.commit()
            create_notification(complaint.citizen_id, 'Complaint Resolved', f'Your complaint "{complaint.title}" has been resolved.')
            flash('Complaint marked as resolved.', 'success')
            return redirect(url_for('dashboard'))

        if user.role == 'citizen' and action == 'feedback':
            rating = request.form.get('rating', type=int) or 0
            comment = request.form.get('comment', '').strip()
            if not 1 <= rating <= 5:
                flash('Please select a rating from 1 to 5.', 'danger')
            elif complaint.citizen_id != user.id or complaint.status != 'resolved':
                flash('Feedback can only be submitted by the filing citizen after resolution.', 'danger')
            elif Feedback.query.filter_by(complaint_id=complaint.id).first():
                flash('Feedback has already been submitted for this complaint.', 'warning')
            else:
                feedback = Feedback(complaint_id=complaint.id, rating=rating, comment=comment)
                db.session.add(feedback)
                db.session.commit()
                flash('Feedback submitted successfully.', 'success')
            return redirect(url_for('dashboard'))

        if action == 'close' and user.role not in {'admin', 'citizen'}:
            flash('Only the filing citizen or an admin can close a complaint.', 'danger')
            return redirect(url_for('complaint_detail', complaint_id=complaint.id))

        if action == 'close' and user.role in {'admin', 'citizen'}:
            if user.role == 'citizen' and complaint.citizen_id != user.id:
                flash('Only the filing citizen can close this complaint.', 'danger')
                return redirect(url_for('complaint_detail', complaint_id=complaint.id))
            comment = request.form.get('close_comment', '').strip()
            if not comment:
                flash('A comment is required before closing the complaint.', 'danger')
                return redirect(url_for('complaint_detail', complaint_id=complaint.id))
            if complaint.status != 'resolved':
                flash('A complaint can only be closed after the officer marks it resolved.', 'danger')
                return redirect(url_for('complaint_detail', complaint_id=complaint.id))
            if complaint.status == 'closed':
                flash('This complaint is already closed.', 'warning')
                return redirect(url_for('complaint_detail', complaint_id=complaint.id))
            db.session.add(ComplaintComment(complaint_id=complaint.id, user_id=user.id, text=comment))
            complaint.status = 'closed'
            db.session.commit()
            create_notification(complaint.citizen_id, 'Complaint Closed', f'Your complaint "{complaint.title}" has been closed.')
            flash('Complaint closed successfully.', 'success')
            return redirect(url_for('dashboard'))

    return render_template('complaint_detail.html', complaint=complaint, user=user, officers=officers, departments=departments)


@app.route('/complaint/<int:complaint_id>/photo/<int:photo_id>')
@login_required()
def complaint_photo(user, complaint_id, photo_id):
    complaint = Complaint.query.get_or_404(complaint_id)
    if user.role != 'admin' and user.id not in {complaint.citizen_id, complaint.officer_id}:
        abort(403)

    photo = ComplaintPhoto.query.filter_by(id=photo_id, complaint_id=complaint.id).first_or_404()
    filename = secure_filename(photo.filename)
    image_path = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.isfile(image_path):
        image_path = os.path.join(LEGACY_UPLOAD_FOLDER, filename)
    if not os.path.isfile(image_path):
        abort(404)
    return send_file(image_path, conditional=True, max_age=3600)


@app.route('/notifications')
@login_required()
def notifications(user):
    items = Notification.query.filter_by(user_id=user.id).order_by(Notification.created_at.desc()).all()
    return render_template('notifications.html', notifications=items, user=user)


@app.route('/notifications/<int:notification_id>/read')
@login_required()
def mark_notification_read(user, notification_id):
    notification = Notification.query.filter_by(id=notification_id, user_id=user.id).first_or_404()
    notification.is_read = True
    db.session.commit()
    flash('Notification marked as read.', 'success')
    return redirect(url_for('notifications'))


@app.context_processor
def inject_user():
    user = None
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
    return dict(current_user=user, csrf_token=get_csrf_token())


with app.app_context():
    db.create_all()
    create_seed_data()


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=os.getenv('FLASK_DEBUG', '').lower() == 'true')
