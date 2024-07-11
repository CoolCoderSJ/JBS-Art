from flask import Flask, render_template, session, request, redirect, url_for, flash
from flask_session import Session

from appwrite.client import Client
from appwrite.services.databases import Databases
from appwrite.query import Query
from appwrite.services.users import Users
from appwrite.services.storage import Storage
from appwrite.input_file import InputFile

from argon2 import PasswordHasher
ph = PasswordHasher()

import os
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)

app.config['SESSION_TYPE'] = 'filesystem'
app.config['SECRET_KEY'] = 'super secret'
app.config['SESSION_PERMANENT'] = True

Session(app)

client = (Client()
    .set_endpoint(f'{os.environ["APPWRITE_HOST"]}/v1') 
    .set_project(os.environ['APPWRITE_ID'])               
    .set_key(os.environ['APPWRITE_KEY']))   
db = Databases(client)
users = Users(client)
storage = Storage(client)

def get_all_docs(data, collection, queries=[]):
    docs = []
    offset = 0
    ogq = queries.copy()
    while True:
        queries = ogq.copy()
        queries.append(Query.offset(offset))
        queries.append(Query.limit(100))
        results = db.list_documents(data, collection, queries=queries)
        if len(docs) == results['total']:
            break
        results = results['documents']
        docs += results
        offset += len(results)
    return docs

def get_all_users(queries=[]):
    docs = []
    offset = 0
    ogq = queries.copy()
    while True:
        queries = ogq.copy()
        queries.append(Query.offset(offset))
        queries.append(Query.limit(100))
        results = users.list(queries=queries)
        if len(docs) == results['total']:
            break
        results = results['users']
        docs += results
        offset += len(results)
    return docs


@app.route('/')
def index():
    user = session.get('user', None)
    role = None
    if user:
        role = users.get(user)['labels'][0]

    return render_template('index.html', role=role)

@app.get('/login')
def login():
    return render_template('login.html')

@app.post('/login')
def login_post():
    email = request.form['email']
    password = request.form['password']

    allusers = users.list(queries=[Query.equal('email', email)])['users']
    if len(allusers) == 0:
        uid = users.create('unique()', email=email, name=email.split("@")[0], password=password)['$id']
        users.update_labels(uid, ['participant'])
        session['user'] = uid
        flash('Logged in successfully!')
        return redirect(url_for('index'))
    
    user = allusers[0]
    try:
        ph.verify(user['password'], password)
    except: 
        flash('Incorrect password')
        return redirect(url_for('login'))
   
    uid = user['$id']
    session['user'] = uid

    flash('Logged in successfully!')
    return redirect(url_for('index'))

@app.get('/logout')  
def logout():
    session.pop('user', None)
    flash('Logged out successfully!')
    return redirect(url_for('index'))


@app.get('/contests')
def contests():
    user = session.get('user', None)
    role = None
    if user:
        role = users.get(user)['labels'][0]

    contests = get_all_docs("data", "contests")
    return render_template('contests.html', contests=contests, role=role)

@app.get('/contest/new')
def new_contest():
    user = session.get('user', None)
    role = None
    if user:
        role = users.get(user)['labels'][0]
    if role != 'admin':
        flash('You are not authorized to create contests')
        return redirect(url_for('index'))
    
    return render_template('new_contest.html')

@app.post('/contest/new')
def new_contest_post():
    user = session.get('user', None)
    role = None
    if user:
        role = users.get(user)['labels'][0]
    if role != 'admin':
        flash('You are not authorized to create contests')
        return redirect(url_for('index'))

    name = request.form['name']
    desc = request.form['desc']
    contest = db.create_document("data", "contests", "unique()", {"name": name, "description": desc})
    flash('Contest created successfully!')
    return redirect(f"/contest/{contest['$id']}")

@app.get('/contest/<cid>')
def contest(cid):
    user = session.get('user', None)
    role = None
    if user:
        role = users.get(user)['labels'][0]

    contest = db.get_document("data", "contests", cid)
    submissions = get_all_docs("data", "submissions", [Query.equal('contestId', cid)])
    allusers = get_all_users()
    allusers = {user['$id']: user['name'] for user in allusers}
    print(allusers)

    winners = [submission for submission in submissions if submission['winner']]
    return render_template('contest.html', contest=contest, role=role, submissions=submissions, users=allusers, winners=winners, userId=user)

@app.get('/contest/<cid>/close')
def close_contest(cid):
    user = session.get('user', None)
    role = None
    if user:
        role = users.get(user)['labels'][0]
    if role != 'admin':
        flash('You are not authorized to close contests')
        return redirect(url_for('index'))
    
    contest = db.get_document("data", "contests", cid)
    if not contest['closed']: contest['closed'] = False     # check for None
    db.update_document("data", "contests", cid, {"closed": bool(contest['closed'] ^ 1)})
    flash('Contest status changed successfully!')
    return redirect(f"/contest/{cid}")

@app.get('/contest/<cid>/edit')
def edit_contest(cid):
    user = session.get('user', None)
    role = None
    if user:
        role = users.get(user)['labels'][0]
    if role != 'admin':
        flash('You are not authorized to edit contests')
        return redirect(url_for('index'))
    
    contest = db.get_document("data", "contests", cid)
    return render_template('edit_contest.html', role=role, contest=contest)


@app.post('/contest/<cid>/edit')
def edit_contest_post(cid):
    user = session.get('user', None)
    role = None
    if user:
        role = users.get(user)['labels'][0]
    if role != 'admin':
        flash('You are not authorized to edit contests')
        return redirect(url_for('index'))

    name = request.form['name']
    desc = request.form['desc']
    db.update_document("data", "contests", cid, {"name": name, "description": desc})
    flash('Contest updated successfully!')
    return redirect(f"/contest/{cid}")


@app.get('/contest/<cid>/delete')
def delete_contest(cid):
    user = session.get('user', None)
    role = None
    if user:
        role = users.get(user)['labels'][0]
    if role != 'admin':
        flash('You are not authorized to delete contests')
        return redirect(url_for('index'))
    
    submissions = get_all_docs("data", "submissions", [Query.equal('contestId', cid)])
    for sub in submissions:
        db.delete_document("data", "submissions", sub['$id'])

    db.delete_document("data", "contests", cid)
    flash('Contest deleted successfully!')
    return redirect(url_for('contests'))


@app.get('/contest/<cid>/submit')
def submit(cid):
    user = session.get('user', None)
    if not user: 
        flash('You need to login to submit')
        return redirect(url_for('login'))
    role = None
    if user:
        role = users.get(user)['labels'][0]
    name = users.get(user)['name']
    contest = db.get_document("data", "contests", cid)
    return render_template('submit.html', contest=contest, role=role, name=name)

@app.post('/contest/<cid>/submit')
def submit_post(cid):
    user = session.get('user', None)
    if not user: 
        flash('You need to login to submit')
        return redirect(url_for('login'))
    
    fileSent = request.files['file']
    file = storage.create_file("submissions", "unique()", InputFile.from_bytes(fileSent.read(), fileSent.filename, fileSent.content_type))
    
    db.create_document("data", "submissions", "unique()", {"contestId": cid, "userId": user, "title": request.form['title'], "description": request.form['description'], "fileId": file['$id']})
    flash('Submission successful!')
    return redirect(f"/contest/{cid}")


@app.get('/contest/<cid>/submission/<sid>/edit')
def edit_submission(cid, sid):
    user = session.get('user', None)
    if not user: 
        flash('You need to login to edit submission')
        return redirect(url_for('login'))
    role = None
    if user:
        role = users.get(user)['labels'][0]
    
    submission = db.get_document("data", "submissions", sid)
    contest = db.get_document("data", "contests", cid)

    if submission['userId'] != user and role != 'admin':
        flash('You are not authorized to edit this submission')
        return redirect(f"/contest/{cid}")

    return render_template('edit_submission.html', submission=submission, contest=contest, role=role)

@app.post('/contest/<cid>/submission/<sid>/edit')
def edit_submission_post(cid, sid):
    user = session.get('user', None)
    if not user: 
        flash('You need to login to edit submission')
        return redirect(url_for('login'))
    role = None
    if user:
        role = users.get(user)['labels'][0]
    
    submission = db.get_document("data", "submissions", sid)

    if submission['userId'] != user and role != 'admin':
        flash('You are not authorized to edit this submission')
        return redirect(f"/contest/{cid}")

    file = None
    if "file" in request.files:
        fileSent = request.files['file']
        try: file = storage.create_file("submissions", "unique()", InputFile.from_bytes(fileSent.read(), fileSent.filename, fileSent.content_type))
        except: pass

    db.update_document("data", "submissions", sid, {"title": request.form['title'], "description": request.form['description']})
    if file:
        db.update_document("data", "submissions", sid, {"fileId": file['$id']})

    flash('Submission updated successfully!')
    return redirect(f"/contest/{cid}")


@app.get('/contest/<cid>/submission/<sid>/winner')
def make_winner(cid, sid):
    user = session.get('user', None)
    role = None
    if user:
        role = users.get(user)['labels'][0]
    if role != 'admin':
        flash('You are not authorized to make winners')
        return redirect(url_for('index'))
    
    submission = db.get_document("data", "submissions", sid)
    if not submission['winner']: submission['winner'] = False     # check for None
    db.update_document("data", "submissions", sid, {"winner": bool(submission['winner'] ^ 1)})
    flash('Winner status changed successfully!')
    return redirect(f"/contest/{cid}")

@app.get('/contest/<cid>/submission/<sid>/delete')
def delete_submission(cid, sid):
    user = session.get('user', None)
    role = None
    if user:
        role = users.get(user)['labels'][0]
    if role != 'admin':
        flash('You are not authorized to delete submissions')
        return redirect(url_for('index'))
    
    file = db.get_document("data", "submissions", sid)['fileId']
    storage.delete_file("submissions", file)

    db.delete_document("data", "submissions", sid)
    flash('Submission deleted successfully!')
    return redirect(f"/contest/{cid}")


@app.route('/settings')
def profile():
    user = session.get('user', None)
    if not user: 
        flash('You need to login to view profile')
        return redirect(url_for('login'))
    role = users.get(user)['labels'][0]
    return render_template('settings.html', user=users.get(user), role=role)

@app.post('/settings')
def save_settings():
    user = session.get('user', None)
    if not user: 
        flash('You need to login to save settings')
        return redirect(url_for('login'))
    
    name = request.form['name']
    password = request.form['password']

    users.update_name(user, name)
    if password:
        users.update_password(user, password)

    flash('Settings saved successfully!')
    return redirect(url_for('profile'))

@app.get('/me/submissions')
def my_submissions():
    user = session.get('user', None)
    if not user: 
        flash('You need to login to view submissions')
        return redirect(url_for('login'))
    role = users.get(user)['labels'][0]

    submissions = get_all_docs("data", "submissions", [Query.equal('userId', user)])
    contests = get_all_docs("data", "contests")
    contests = {contest['$id']: {
        "name": contest['name'],
        "closed": contest['closed']
    } for contest in contests}

    return render_template('my_submissions.html', submissions=submissions, role=role, user=users.get(user), contests=contests)


@app.get('/winners')
def winners():
    user = session.get('user', None)
    role = None
    if user:
        role = users.get(user)['labels'][0]

    submissions = get_all_docs("data", "submissions", [Query.equal('winner', True)])
    contests = get_all_docs("data", "contests")
    contests = {contest['$id']: contest['name'] for contest in contests}
    
    s = {}
    for c in contests.keys():
        s[c] = []
    for submission in submissions:
        s[submission['contestId']].append(submission)
    submissions = s
    
    return render_template('winners.html', submissions=submissions, role=role, user=users.get(user), contests=contests)

app.run(host='0.0.0.0', port=2308, debug=True)