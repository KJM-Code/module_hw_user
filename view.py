from flask import Blueprint
from . import database
from flask import session,redirect,request,url_for,render_template,current_app
from imports.bootstrap import bootstrap
from imports.database import db
from .forms.user_forms import LoginForm,RegisterForm,Change_Login_Password
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user,current_user,login_required,logout_user
from .base_settings import Main,Schema




@Main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'GET':
        session['url'] = request.args.get('next')
    if form.validate_on_submit():
        user = database.SYS_USERS.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                dest = session['url']
                session['url'] = None
                try:
                    dest_url = dest
                except:

                    return redirect(url_for('General.main'))
                return redirect(dest_url)
        return """<h1>Invalid username or password</h1>
                    <meta http-equiv="refresh" content="3;{}" />""".format(url_for('Users.login'))

    return render_template('/user/login.html', form=form,user_registration_disabled=current_app.config['USER_REGISTRATION_DISABLED'])


@Main.route('/register', methods=['GET', 'POST'])
def register():
    if current_app.config['USER_REGISTRATION_DISABLED'] == True:
        return """<h1>Registration is disabled. Please log in with an existing account.</h1>
                    <meta http-equiv="refresh" content="3;{}" />""".format(url_for("Users.login"))
    form = RegisterForm()

    if form.validate():
        hashed_password = generate_password_hash(form.password.data, method='scrypt')

        try:
            new_user = database.SYS_USERS(username=form.username.data, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
        except Exception as e:

            err = str(e)
            if 'UNIQUE constraint failed:' in err:
                Error = 'The following inputs already exist in the database: '
                if 'user.username' in err:
                    Error += 'User'

                return render_template('user/register.html', form=form, error=Error)
            else:
                print(__name__, 'USER CREATION ERROR', e)
                raise e

        user = database.SYS_USERS.query.filter_by(username=form.username.data).first()
        if check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('General.main'))
        return '<h1>Error when creating user</h1>'
    return render_template('/user/register.html', form=form)


@Main.route('/update_password', methods=['GET', 'POST'])
def change_login_password():
    if current_user.is_authenticated:
        form = Change_Login_Password()
        if form.validate():
            user = database.SYS_USERS.query.filter_by(username=form.username.data).first()
            if check_password_hash(user.password, form.password.data):
                hashed_password_change = generate_password_hash(form.new_password.data, method='scrypt')
                update_this = database.SYS_USERS.query.filter_by(username=form.username.data).first()
                update_this.password = hashed_password_change
                db.session.commit()
                print("User data updated for:", form.username.data)

                if 'prev_url' in session:
                    url_redirect = session['prev_url']
                else:
                    url_redirect = url_for('General.main')
                return """Account information updated. 
            <meta http-equiv="refresh" content="3;url={}" />""".format(url_redirect)
        return render_template('/user/update_password.html', form=form)

    else:
        return 'Not Logged In'


@Main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('General.main'))
