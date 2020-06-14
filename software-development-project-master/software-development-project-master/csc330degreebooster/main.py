#Login system for Degree Booster
from __future__ import print_function
from flask import render_template, flash, redirect, url_for, request, Flask
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.urls import url_parse
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import Form,IntegerField, TextField, PasswordField, validators, SubmitField, SelectField, BooleanField
from wtforms.validators import ValidationError, DataRequired, EqualTo
from flask_bootstrap import Bootstrap
from flask_moment import Moment
from flask_wtf import FlaskForm
import sys
import pymysql, getpass , sys
from flask_mail import Mail, Message
import os

'''
    sprint 1
    Ortega:login edited by
    Kenn: sign up edited by
    waiyat: attaching database to login ,attaching database to signup
            ,transfering excell data into database
    kevin: login database creating table
    asil: create table for a whole database except login
    ----------------------------------------------------------------------------------------
    sprint 2
    waiyat:oversees database,add page, remove page , waiting List
    Ortega : working with waiyat in the waiting list
    aseel: add course page in the faculty
    kevin : Notification
    kenn : doing Nothing
    -----------------------------------------------------------------------------------------
    sprint3
    waiyat:removing remove page and add them in waiting list, fixing notivication with kevin,
            fixing the adding couses more simple, working with aseel on the waiting list,


    Ortega : providing back up and idea on the adding page
    aseel: fixing course page in the faculty, working with waiyat to add waiting_list
            , working with waiyat adding admin page

    kevin :fixing Notification with waiyat, editing the documentation
    kenn : doing Nothing


important # NOTE:
xyl is a global that containing the account ID (like student id)
'''
global opas
opas='1291'

global mailpass
mailpass='AsFNWaH12'

global mailadd
mailadd= 'hamdaniw1.southernct@gmail.com'
#login form ( subclassesd from FlaskForm)
class LoginForm(FlaskForm):
    #add an if statement that checks if the username is legible
    #userName must be banner id number or email address that connects to the banner id of student and faculty
    username =TextField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators = [ DataRequired() ] )
    remember_me = BooleanField('keep me logged in') #represents a checkbox
    submit = SubmitField('Sign In')

class searchForm(FlaskForm):
    type = SelectField('crn or sub or instructor:',choices=[("sub","sub"),("crn","crn"),("instructor","instructor")])
    value =TextField('value:', validators=[DataRequired()])
    submit = SubmitField('search')

#registration class will go here
class RegistrationForm(FlaskForm):
    username = TextField('Username', validators=[validators.DataRequired()])
    password = PasswordField('New Password', validators=[validators.DataRequired()])
    role = TextField('student or faculty?', validators=[validators.DataRequired()])
    firstName = TextField('First Name', validators=[validators.DataRequired()])
    lastName = TextField('Last Name', validators=[validators.DataRequired()])
    type = TextField('freshmen,sophmore,junior, senior, or faculty:', validators=[validators.DataRequired()])
    email = TextField('Email Address', validators=[validators.DataRequired()])
    scsuId=TextField('enter your exaple scsu ID being assign to you:', validators=[validators.DataRequired()])
    submit = SubmitField('Register')

#add courses form goes here
class addCoursesForm(FlaskForm):
    crn =TextField('crn', validators=[DataRequired()])
    sub = TextField('sub', validators = [ DataRequired() ] )
    crse = TextField('crse', validators = [ DataRequired() ] )
    section = TextField('section', validators = [ DataRequired() ] )
    title = TextField('title', validators = [ DataRequired() ] )
    day = TextField('days', validators = [ DataRequired() ] )
    add = SubmitField('add')

class facultyaddCoursesForm(FlaskForm):
    studentid = TextField('enter student id', validators=[validators.DataRequired()])
    crn =TextField('crn', validators=[DataRequired()])
    sub = TextField('sub', validators = [ DataRequired() ] )
    crse = TextField('crse', validators = [ DataRequired() ] )
    section = TextField('section', validators = [ DataRequired() ] )
    title = TextField('title', validators = [ DataRequired() ] )
    day = TextField('days', validators = [ DataRequired() ] )
    add = SubmitField('add')

class removeCoursesForm(FlaskForm):
    crn =TextField('crn', validators=[DataRequired()])
    sub = TextField('sub', validators = [ DataRequired() ] )
    crse = TextField('crse', validators = [ DataRequired() ] )
    section = TextField('section', validators = [ DataRequired() ] )
    remove = SubmitField('remove')

class searchclassform(FlaskForm):
    type = SelectField('crn or sub :',choices=[("sub","sub"),("crn","crn")])
    value =TextField('value:')
    submit = SubmitField('search')

class adminform(FlaskForm):
    crn =TextField('crn', validators=[DataRequired()])
    sub = TextField('sub', validators = [ DataRequired() ] )
    crse = TextField('crse', validators = [ DataRequired() ] )
    section = TextField('section', validators = [ DataRequired() ] )
    title = TextField('title', validators = [ DataRequired() ] )
    day = TextField('days', validators = [ DataRequired() ] )
    time = TextField('time', validators = [ DataRequired() ] )
    instructor = TextField('instructor', validators = [ DataRequired() ] )
    type = TextField('type', validators = [ DataRequired() ] )
    seat = TextField('seat', validators = [ DataRequired() ] )
    enrolled = TextField('enrolled', validators = [ DataRequired() ] )
    add = SubmitField('add courses')

#user class part of registration
class User(UserMixin):
    def __init__(self, username, password, role,accId):
        self.id = username
        #print(userid, file=sys.stderr)
        self.accId=accId
        global xyl
        xyl=self.accId
        print(xyl, file=sys.stderr)
        #hash the password andn output it to stderr
        self.pass_hash = generate_password_hash(password)
        print(self.pass_hash, file=sys.stderr)
        self.role = role

#creating the Flask app object and login manager
app = Flask(__name__)
app.db = None
app.config['SECRET_KEY'] = 'secretsecretkey'
bootstrap = Bootstrap(app)
moment = Moment(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

#email configuration
app.config.update(
        MAIL_SERVER='smtp.gmail.com',
        MAIL_PORT=465,
        MAIL_USE_TLS=False,
        MAIL_USE_SSL=True,
        MAIL_USERNAME=mailadd,
        MAIL_PASSWORD=mailpass,
        MAIL_DEFAULT_SENDER = ('degreebooster', mailadd),
        SECRET_KEY='waiyat the awesome programer')
mail= Mail(app)

def connectdb():
    if not app.db:
        db_IP = '35.238.142.92'
        # getpass so that password is not echoed to the terminal
        pswd = opas
        app.db = pymysql.connect(db_IP, 'root', pswd, 'degreebooster')
    else:
        print('Connected!', file=sys.stderr)

global user_db
user_db={}

#dlist position 3= student Id or faculty Id
#dlist position 4= email Address
global dblist
dblist={}

def mydatabase():

    if not app.db:
        connectdb()

    c = app.db.cursor()
    c.execute('SELECT * from login')
    login_list = c.fetchall()
    for mylogin in login_list:
        user_db[str(mylogin[0])]=User(str(mylogin[0]),str(mylogin[1]),str(mylogin[2]),mylogin[7])
        dblist[str(mylogin[0])]=[str(mylogin[0]),str(mylogin[1]),str(mylogin[2]),mylogin[7],mylogin[6]]




@app.route('/registration', methods=['GET', 'POST'])
def register():
    #waiyat connect db connection
    if not app.db:
        connectdb()
    conn=app.db.cursor()

    username = None
    password = None
    role = None
    firstName = None
    lastName = None
    email = None
    scsuId=None
    forms = RegistrationForm()
    if forms.validate_on_submit():
        username = forms.username.data
        global num
        num= str(username)
        password = forms.password.data
        role = forms.role.data
        firstName = forms.firstName.data
        lastName = forms.lastName.data
        type=forms.type.data
        email = forms.email.data
        scsuId=forms.scsuId.data
        # waiyat Insert Row into db
        query='INSERT INTO login values("{}","{}","{}","{}","{}","{}","{}",{})'.format(str(username),str(password),str(role),str(firstName),str(lastName),str(type),str(email),scsuId)
        conn.execute(query)
        app.db.commit()
        mydatabase()
        flash('Successful')
    else:
        flash('All the form fields are required.')
    return render_template('registration.html', title='Registration', forms=forms )

#Returns True if logged in user has "faculty" role, False otherwise.
def is_faculty():
    if current_user:
        if current_user.role == 'faculty':
            return True
        else:
            return False
    else:
        print('User not authenticated.', file=sys.stderr)

def is_student():
    if current_user:
        if current_user.role=='student':
            return True
        else:
            return False
    else:
        print("User not authenticated.", file=sys.stderr)

#Login manager uses this functin to manage user sessions.
# Function does a lookup by id and returns the User object if it exists, None otherwise
@login_manager.user_loader
def load_user(id):
    return user_db.get(id) # this line will be changed to the query for the database instead of the dictionary used here for testing purposes only


#this mimics a situation where a non-admin user attempts to access an admin-only area.
# @login_required ensures that only authenticaed users may access this route.
@app.route('/faculty_only', methods=['GET', 'POST'])
@login_required
def faculty_only():
    #determine if current user is faculty
    if is_faculty():
        if not app.db:
            connectdb()
        conn=app.db.cursor()
        studentid=None
        crn=None
        crse=None
        sub=None
        section=None
        title=None
        day=None
        fforms= facultyaddCoursesForm()
        if fforms.validate_on_submit():
            studentid=fforms.studentid.data
            crn=fforms.crn.data
            sub=fforms.sub.data
            crse=fforms.crse.data
            section=fforms.section.data
            title=fforms.title.data
            day=fforms.day.data
            conn.execute('insert INTO waitList values({},{},"{}","{}","{}","{}","{}")'.format(int(studentid),int(crn),crse,sub,section,title,day))
            app.db.commit()
            flash('Successful')
        return render_template('faculty.html',fforms=fforms)

@app.route('/waiting_list2',methods=['GET', 'POST'])
@login_required
def waiting_list2():
    if is_faculty():
        if not app.db:
            connectdb()
        conn=app.db.cursor()
        crn=None
        crse=None
        sub=None
        section=None
        title=None
        day=None
        instructor=None
        rforms= removeCoursesForm()
        #using join to grab a schedule
        conn.execute('select w.idstudent,w.crn,w.crse,w.sub,w.section,w.title,w.days,l.FirstName,l.LastName from waitList w join login l on w.idstudent= l.idstudent ')
        wlist=conn.fetchall()
        return render_template('waiting_list2.html',wlist=wlist)

@app.route('/zzz', methods=['GET', 'POST'])
@login_required
def admin_privilage():
    if is_faculty():
        if not app.db:
            connectdb()
        conn=app.db.cursor()
        crn =None
        sub = None
        crse = None
        section = None
        title = None
        day = None
        time = None
        instructor = None
        type = None
        seat = None
        enrolled = None
        adform=adminform()
        if adform.validate_on_submit():
            crn =adform.crn.data
            sub = adform.sub.data
            crse = adform.crse.data
            section = adform.section.data
            title = adform.title.data
            day = adform.day.data
            time = adform.time.data
            instructor = adform.instructor.data
            type = adform.type.data
            seat = adform.seat.data
            enrolled = adform.enrolled.data
            conn.execute('insert into schedule values({},"{}",{},"{}","{}","{}","{}","{}","{}",{},{})'.format(crn,sub,crse,section,title,day,time,instructor,type,seat,enrolled))
            app.db.commit()
            flash('Successful')
        return render_template('admin.html',adform=adform)

@app.route('/adminremove', methods=['GET', 'POST'])
@login_required
def adminremove_privilage():
    if is_faculty():
        if not app.db:
            connectdb()
        conn=app.db.cursor()
        crn =None
        sub = None
        crse = None
        section = None
        adform=removeCoursesForm()
        conn.execute('select * from empty')
        schlist=conn.fetchall()
        type=None
        value=None
        bforms=searchclassform()


        if adform.validate_on_submit():
            crn=adform.crn.data
            sub=adform.sub.data
            crse=adform.crse.data
            section=adform.section.data
            conn.execute("delete from schedule where crn ={} and sub ='{}' and crse={} and section='{}'".format(crn,sub,crse,section))
            app.db.commit()
            flash('Successful')
        if bforms.validate_on_submit():
            type=bforms.type.data
            value=bforms.value.data
            conn.execute('select * from schedule where {}="{}"'.format(type,value))
            schlist=conn.fetchall()
        return render_template('adminremove.html',schlist=schlist,adform=adform,bforms=bforms)

#3 functions for student options...(function logic not implemented yet)
@app.route('/course',methods=['GET', 'POST'])
@login_required
def course_status():
    #to make sure this is student
    if is_student():
        mydatabase()
        #if this is not connect to db
        if not app.db:
            connectdb()
        conn=app.db.cursor()
        type=None
        value=None
        sforms=searchForm()
        #this code just to show all the 2626 data in database for now----------------------
        conn.execute('select * from schedule')
        schlist=conn.fetchall()
        #----------------------------------------------------------------------------------
        #------------------------after the submit the sub they ony submit the type-------------
        if sforms.validate_on_submit():
            type=sforms.type.data
            value=sforms.value.data
            conn.execute('select * from schedule where {}="{}"'.format(type,value))
            schlist=conn.fetchall()
            return render_template('course.html',schlist=schlist,sforms=sforms)
        return render_template('course.html',schlist=schlist,sforms=sforms)
        #-------------------------------------------------------------------------------------
    if is_faculty():
        mydatabase()
        #if this is not connect to db
        if not app.db:
            connectdb()
        conn=app.db.cursor()
        type=None
        value=None

        sforms=searchForm()
        #this code just to show all the 2626 data in database for now----------------------
        conn.execute('select * from schedule')
        schlist=conn.fetchall()
        #----------------------------------------------------------------------------------
        #------------------------after the submit the sub they ony submit the type-------------
        if sforms.validate_on_submit():
            type=sforms.type.data
            value=sforms.value.data
            conn.execute('select * from schedule where {}="{}"'.format(type,value))
            schlist=conn.fetchall()
            return render_template('course.html',schlist=schlist,sforms=sforms)



        return render_template('course.html',schlist=schlist,sforms=sforms)
        #-------------------------------------------------------------------------------------

@app.route('/waiting_list',methods=['GET', 'POST'])
@login_required
def waiting_list():
    if is_student():
        if not app.db:
            connectdb()
        conn=app.db.cursor()
        crn=None
        crse=None
        sub=None
        section=None
        rforms= removeCoursesForm()

        #using join to grab a schedule
        conn.execute('select s.crn,s.sub,s.crse,s.Section,s.title,s.days,s.time,s.instructor,s.type,s.seats,s.enrolled from schedule s join waitList w on s.crn = w.crn and s.crse = w.crse and s.sub = w.sub where w.idStudent = {}'.format(int(userxyl)))
        wlist=conn.fetchall()
        if rforms.validate_on_submit():
            crn=rforms.crn.data
            sub=rforms.sub.data
            crse=rforms.crse.data
            section=rforms.section.data
            conn.execute('delete from waitList where idStudent={} and crn={} and sub="{}" and crse="{}" and section="{}"'.format(userxyl,crn,sub,crse,section))
            app.db.commit()
            flash('Successful')
            return render_template('waiting_list.html',wlist=wlist, rforms=rforms)

        return render_template('waiting_list.html',wlist=wlist, rforms=rforms)

#waiyat and Asil work on add_course
@app.route('/add',methods=['GET', 'POST'])
@login_required
def add_course():
    if is_student():
        if not app.db:
            connectdb()
        conn=app.db.cursor()
        crn=None
        crse=None
        sub=None
        section=None
        title=None
        day=None
        aforms= addCoursesForm()
        type=None
        value=None
        bforms=searchclassform()
        conn.execute('select * from empty')
        schlist=conn.fetchall()
        if bforms.validate_on_submit():
            type=bforms.type.data
            value=bforms.value.data
            conn.execute('select * from schedule where {}="{}"'.format(type,value))
            schlist=conn.fetchall()

        if aforms.validate_on_submit():
            crn=aforms.crn.data
            sub=aforms.sub.data
            crse=aforms.crse.data
            section=aforms.section.data
            title=aforms.title.data
            day=aforms.day.data
            conn.execute('insert INTO waitList values({},{},"{}","{}","{}","{}","{}")'.format(userxyl,crn,crse,sub,section,title,day))
            app.db.commit()
            flash('Successful')
    return render_template('add.html', schlist=schlist,aforms=aforms , bforms=bforms)

#waiyat and Asil work on remove_course

@app.route('/')
@app.route('/success')
@login_required
def success():
    global userxyl
    userxyl=dblist[usern][3]
    global mailxyl
    mailxyl = dblist[usern][4]
    return render_template('success.html',name=current_user.id)

@app.route('/login', methods =['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect( url_for('success') )
    # check login input credentials
    form = LoginForm()
    if form.validate_on_submit():
        mydatabase()
        global usern
        usern=form.username.data
        user = user_db[usern] #database query will go here to get user

        #validate user
        valid_password = check_password_hash(user.pass_hash, form.password.data)
        if user is None or not valid_password :
            print('Invalid username or password', file=sys.stderr) #console output
            flash('Invalid ursername or password') #displays this message
            redirect(url_for('success'))
        else:
            login_user(user, form.remember_me.data)
            return redirect(url_for('success'))
    return render_template('login.html', title='Sign In', form=form )
#logging out is managed by login manager
#log out option appears on the navbar only after a user logs on successfully
@app.route('/logout')
def logout():
    logout_user()
    flash("You have been logged out.") #displays message
    return redirect(url_for('success'))

#function for registration
