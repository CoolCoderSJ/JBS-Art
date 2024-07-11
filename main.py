from flask import Flask, render_template, session, request, redirect, url_for, flash
from flask_session import Session

from appwrite.client import Client
from appwrite.services.databases import Databases
from appwrite.query import Query
from appwrite.services.users import Users

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
    print(allusers)
    return render_template('contest.html', contest=contest, role=role, submissions=submissions, users=allusers)

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


app.run(host='0.0.0.0', port=2308, debug=True)