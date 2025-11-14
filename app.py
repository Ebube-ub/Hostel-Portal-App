from flask import Flask, render_template, url_for, redirect, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_scss import Scss
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Email, Length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)
Scss(app)
bcrypt = Bcrypt(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hostel.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'
db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    selected_room = db.Column(db.String(10))  # e.g., Room101
    complaint = db.Column(db.String(200), unique=True, nullable=True)


class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(150))




class ComplaintForm(FlaskForm):
    complaint = StringField(validators=[Length(min=4, max=220)], render_kw={"placeholder": "Any Complaint?"})
    submit = SubmitField('Submit Complaint')


class RegisterForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(message='Invalid email'), Length(max=150)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=150)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Sign Up')

    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()


        if existing_user_email:
            raise ValidationError('That user already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    email = StringField(validators=[InputRequired(), Email(message='Invalid email'), Length(max=150)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=150)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')


    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email:
            flash('That user already exists. Please choose a different one.')
            raise ValidationError('That user already exists. Please choose a different one.')



@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    error = None

    if True: #form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
                
            else:
                flash('Invalid username or password')
                error = 'Invalid username or password'
    return render_template('login.html', form=form, error=error, from_signup=True)



@app.route('/dashboard', methods=['GET', 'POST'])  
@login_required  
def dashboard():
    
    rooms = Room.query.all()  # Fetch all rooms  
    # Get list of room names already selected by some user
    taken_rooms = [u.selected_room for u in User.query.filter(User.selected_room.isnot(None)).all()]  

    error = None  
    if request.method == 'POST':  
        selected_room = request.form.get('room_name')  
        # If room is taken and it’s not already their own selected room
        if selected_room in taken_rooms and selected_room != current_user.selected_room:  
            error = "Sorry, that room is already taken!"  
        else:  
            current_user.selected_room = selected_room  # assign room to user  
            db.session.commit()  
            flash('Room successfully picked')
            return redirect(url_for('dashboard'))  

    # Render dashboard passing user, rooms, taken list, error if any
    return render_template('dashboard.html', user=current_user, rooms=rooms, taken_rooms=taken_rooms, error=error)  





@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out')
    return redirect(url_for('index'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(email=form.email.data, password=hashed_password)

        db.session.add(new_user)
        db.session.commit()
        flash('Signed Up Successfuly')
        return redirect(url_for('signup'))
       
    
    return render_template('signup.html', form=form)


@app.route('/select_room/<room_number>')
@login_required
def select_room(room_number):
    current_user.selected_room = room_number
    db.session.commit()
    return redirect(url_for('dashboard'))


@app.route('/cancel_selection', methods=['POST'])
@login_required
def cancel_selection():
    current_user.selected_room = None  # Clear the user's selection
    db.session.commit()                # Save changes to the database
    flash('Booking canceled')
    return redirect(url_for('dashboard'))

@app.route('/bookings', methods=['GET', 'POST'])
@login_required
def bookings():
    form = ComplaintForm()
    if form.validate_on_submit():
        current_user.complaint = form.complaint.data
        db.session.commit()
        flash('Complaint Submitted Successfully')
        return redirect(url_for('bookings'))

    return render_template('bookings.html',form=form)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()

        # Only create rooms if table is empty
        if Room.query.count() == 0:
            room_list = [Room(name=f"Room{num}") for num in range(101, 131)]
            db.session.bulk_save_objects(room_list)
            db.session.commit()

    app.run(debug=True)

    
