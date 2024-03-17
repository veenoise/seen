from dotenv import load_dotenv
import os
from flask import Flask, jsonify, url_for, render_template, session, redirect, request
from markupsafe import escape
import cs50
import hashlib
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import threading

load_dotenv()

app = Flask(__name__)
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://",
)

app.secret_key = os.getenv("SECRET_KEY").encode('utf-8')

salt = os.getenv("SECRET_SALT").encode('utf-8') * 2

pbkdf_iteration = 600_000

db = cs50.SQL("sqlite:///accounts.db")

db_lock = threading.Lock()

@app.route("/", methods=['GET'])
def index():    
    # Check if logged in
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Check if user does not have a team
    if 'team' not in session:        
        return redirect(url_for('prompt'))
    
    if session['role'] == 'Pending':
        return redirect(url_for('team'))
        
    return render_template('index.html')

@app.route("/get_index", methods=['GET'])
def get_index():
    # Check if logged in
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Check if user does not have a team
    if 'team' not in session:        
        return redirect(url_for('prompt'))
    
    tid = db.execute("SELECT team_id FROM accounts LEFT JOIN teams ON accounts.team_id = teams.id WHERE name = ?", session['team'])[0]['team_id']
    row = db.execute("SELECT * FROM questions WHERE team_id = ?", tid)[0]
    score = db.execute("SELECT score from teams WHERE id = ?", tid)[0]['score']

    data = {
        'team_id': tid,
        'row': row,
        'score': score
    }

    return jsonify(data)

@app.route("/post_index", methods=['POST'])
@limiter.limit("1 per 30 seconds")
def post_index():
    data = request.get_json()    
    name = data['name']
    value = data['value']
    if name == "introButton":
        answer = os.getenv("ANSWER_INTRO")
        if answer == value:
            rows = db.execute("SELECT questions.intro, teams.id FROM teams LEFT JOIN questions ON teams.id = questions.team_id WHERE name = ?", session['team'])
            tid = rows[0]['id']
            with db_lock:
                if rows[0]['intro'] != 0:
                    return redirect(url_for('index'))
                
                highest = db.execute("SELECT intro FROM questions GROUP BY intro ORDER BY intro ASC")
                if len(highest) != 1:
                    highest = highest[1]['intro']
                else:
                    highest = highest[0]['intro']

                if highest == 0:
                    db.execute("UPDATE questions SET intro = ? WHERE team_id = ?", 500, tid)
                
                elif highest != 0:
                    highest -= 10
                    db.execute("UPDATE questions SET intro = ? WHERE team_id = ?", highest, tid)

                up_score = db.execute("SELECT (intro + wod + ten + ct + dsw + mm + bts + ftmt + va + hips + wita) AS sum_row FROM questions WHERE team_id = ?", tid)[0]['sum_row']
                db.execute("UPDATE teams SET score = ? WHERE id = ?", up_score, tid)

    elif name == "wodButton":
        answer = os.getenv("ANSWER_WOTD")
        if answer == value:
            rows = db.execute("SELECT questions.wod, teams.id FROM teams LEFT JOIN questions ON teams.id = questions.team_id WHERE name = ?", session['team'])
            tid = rows[0]['id']
            with db_lock:
                if rows[0]['wod'] != 0:
                    return redirect(url_for('index'))
                
                highest = db.execute("SELECT wod FROM questions GROUP BY wod ORDER BY wod ASC")
                if len(highest) != 1:
                    highest = highest[1]['wod']
                else:
                    highest = highest[0]['wod']

                if highest == 0:
                    db.execute("UPDATE questions SET wod = ? WHERE team_id = ?", 500, tid)
                
                elif highest != 0:
                    highest -= 10
                    db.execute("UPDATE questions SET wod = ? WHERE team_id = ?", highest, tid)

                up_score = db.execute("SELECT (intro + wod + ten + ct + dsw + mm + bts + ftmt + va + hips + wita) AS sum_row FROM questions WHERE team_id = ?", tid)[0]['sum_row']
                db.execute("UPDATE teams SET score = ? WHERE id = ?", up_score, tid)

    elif name == "tenButton":
        answer = os.getenv("ANSWER_TEN")
        if answer == value:
            rows = db.execute("SELECT questions.ten, teams.id FROM teams LEFT JOIN questions ON teams.id = questions.team_id WHERE name = ?", session['team'])
            tid = rows[0]['id']
            with db_lock:
                if rows[0]['ten'] != 0:
                    return redirect(url_for('index'))
                
                highest = db.execute("SELECT ten FROM questions GROUP BY ten ORDER BY ten ASC")
                if len(highest) != 1:
                    highest = highest[1]['ten']
                else:
                    highest = highest[0]['ten']

                if highest == 0:
                    db.execute("UPDATE questions SET ten = ? WHERE team_id = ?", 500, tid)
                
                elif highest != 0:
                    highest -= 10
                    db.execute("UPDATE questions SET ten = ? WHERE team_id = ?", highest, tid)

                up_score = db.execute("SELECT (intro + wod + ten + ct + dsw + mm + bts + ftmt + va + hips + wita) AS sum_row FROM questions WHERE team_id = ?", tid)[0]['sum_row']
                db.execute("UPDATE teams SET score = ? WHERE id = ?", up_score, tid)

    elif name == "ctButton":
        answer = os.getenv("ANSWER_CT")
        if answer == value:
            rows = db.execute("SELECT questions.ct, teams.id FROM teams LEFT JOIN questions ON teams.id = questions.team_id WHERE name = ?", session['team'])
            tid = rows[0]['id']
            with db_lock:
                if rows[0]['ct'] != 0:
                    return redirect(url_for('index'))
                
                highest = db.execute("SELECT ct FROM questions GROUP BY ct ORDER BY ct ASC")
                if len(highest) != 1:
                    highest = highest[1]['ct']
                else:
                    highest = highest[0]['ct']

                if highest == 0:
                    db.execute("UPDATE questions SET ct = ? WHERE team_id = ?", 500, tid)
                
                elif highest != 0:
                    highest -= 10
                    db.execute("UPDATE questions SET ct = ? WHERE team_id = ?", highest, tid)

                up_score = db.execute("SELECT (intro + wod + ten + ct + dsw + mm + bts + ftmt + va + hips + wita) AS sum_row FROM questions WHERE team_id = ?", tid)[0]['sum_row']
                db.execute("UPDATE teams SET score = ? WHERE id = ?", up_score, tid)

    elif name == "dswButton":
        answer = os.getenv("ANSWER_DSW")
        if answer == value:
            rows = db.execute("SELECT questions.dsw, teams.id FROM teams LEFT JOIN questions ON teams.id = questions.team_id WHERE name = ?", session['team'])
            tid = rows[0]['id']
            with db_lock:
                if rows[0]['dsw'] != 0:
                    return redirect(url_for('index'))
                
                highest = db.execute("SELECT dsw FROM questions GROUP BY dsw ORDER BY dsw ASC")
                if len(highest) != 1:
                    highest = highest[1]['dsw']
                else:
                    highest = highest[0]['dsw']

                if highest == 0:
                    db.execute("UPDATE questions SET dsw = ? WHERE team_id = ?", 500, tid)
                
                elif highest != 0:
                    highest -= 10
                    db.execute("UPDATE questions SET dsw = ? WHERE team_id = ?", highest, tid)

                up_score = db.execute("SELECT (intro + wod + ten + ct + dsw + mm + bts + ftmt + va + hips + wita) AS sum_row FROM questions WHERE team_id = ?", tid)[0]['sum_row']
                db.execute("UPDATE teams SET score = ? WHERE id = ?", up_score, tid)

    elif name == "mmButton":
        answer = os.getenv("ANSWER_MM")
        if answer == value:
            rows = db.execute("SELECT questions.mm, teams.id FROM teams LEFT JOIN questions ON teams.id = questions.team_id WHERE name = ?", session['team'])
            tid = rows[0]['id']
            with db_lock:
                if rows[0]['mm'] != 0:
                    return redirect(url_for('index'))
                
                highest = db.execute("SELECT mm FROM questions GROUP BY mm ORDER BY mm ASC")
                if len(highest) != 1:
                    highest = highest[1]['mm']
                else:
                    highest = highest[0]['mm']

                if highest == 0:
                    db.execute("UPDATE questions SET mm = ? WHERE team_id = ?", 500, tid)
                
                elif highest != 0:
                    highest -= 10
                    db.execute("UPDATE questions SET mm = ? WHERE team_id = ?", highest, tid)

                up_score = db.execute("SELECT (intro + wod + ten + ct + dsw + mm + bts + ftmt + va + hips + wita) AS sum_row FROM questions WHERE team_id = ?", tid)[0]['sum_row']
                db.execute("UPDATE teams SET score = ? WHERE id = ?", up_score, tid)

    elif name == "btsButton":
        answer = os.getenv("ANSWER_BTS")
        if answer == value:
            rows = db.execute("SELECT questions.bts, teams.id FROM teams LEFT JOIN questions ON teams.id = questions.team_id WHERE name = ?", session['team'])
            tid = rows[0]['id']
            with db_lock:
                if rows[0]['bts'] != 0:
                    return redirect(url_for('index'))
                
                highest = db.execute("SELECT bts FROM questions GROUP BY bts ORDER BY bts ASC")
                if len(highest) != 1:
                    highest = highest[1]['bts']
                else:
                    highest = highest[0]['bts']

                if highest == 0:
                    db.execute("UPDATE questions SET bts = ? WHERE team_id = ?", 500, tid)
                
                elif highest != 0:
                    highest -= 10
                    db.execute("UPDATE questions SET bts = ? WHERE team_id = ?", highest, tid)

                up_score = db.execute("SELECT (intro + wod + ten + ct + dsw + mm + bts + ftmt + va + hips + wita) AS sum_row FROM questions WHERE team_id = ?", tid)[0]['sum_row']
                db.execute("UPDATE teams SET score = ? WHERE id = ?", up_score, tid)

    elif name == "ftmtButton":
        answer = os.getenv("ANSWER_FTMT")
        if answer == value:
            rows = db.execute("SELECT questions.ftmt, teams.id FROM teams LEFT JOIN questions ON teams.id = questions.team_id WHERE name = ?", session['team'])
            tid = rows[0]['id']
            with db_lock:
                if rows[0]['ftmt'] != 0:
                    return redirect(url_for('index'))
                
                highest = db.execute("SELECT ftmt FROM questions GROUP BY ftmt ORDER BY ftmt ASC")
                if len(highest) != 1:
                    highest = highest[1]['ftmt']
                else:
                    highest = highest[0]['ftmt']

                if highest == 0:
                    db.execute("UPDATE questions SET ftmt = ? WHERE team_id = ?", 500, tid)
                
                elif highest != 0:
                    highest -= 10
                    db.execute("UPDATE questions SET ftmt = ? WHERE team_id = ?", highest, tid)

                up_score = db.execute("SELECT (intro + wod + ten + ct + dsw + mm + bts + ftmt + va + hips + wita) AS sum_row FROM questions WHERE team_id = ?", tid)[0]['sum_row']
                db.execute("UPDATE teams SET score = ? WHERE id = ?", up_score, tid)
    
    elif name == "vaButton":
        answer = os.getenv("ANSWER_VA")
        if answer == value:
            rows = db.execute("SELECT questions.va, teams.id FROM teams LEFT JOIN questions ON teams.id = questions.team_id WHERE name = ?", session['team'])
            tid = rows[0]['id']
            with db_lock:
                if rows[0]['va'] != 0:
                    return redirect(url_for('index'))
                
                highest = db.execute("SELECT va FROM questions GROUP BY va ORDER BY va ASC")
                if len(highest) != 1:
                    highest = highest[1]['va']
                else:
                    highest = highest[0]['va']

                if highest == 0:
                    db.execute("UPDATE questions SET va = ? WHERE team_id = ?", 500, tid)
                
                elif highest != 0:
                    highest -= 10
                    db.execute("UPDATE questions SET va = ? WHERE team_id = ?", highest, tid)

                up_score = db.execute("SELECT (intro + wod + ten + ct + dsw + mm + bts + ftmt + va + hips + wita) AS sum_row FROM questions WHERE team_id = ?", tid)[0]['sum_row']
                db.execute("UPDATE teams SET score = ? WHERE id = ?", up_score, tid)

    elif name == "hipsButton":
        answer = os.getenv("ANSWER_HIPS")
        if answer == value:
            rows = db.execute("SELECT questions.hips, teams.id FROM teams LEFT JOIN questions ON teams.id = questions.team_id WHERE name = ?", session['team'])
            tid = rows[0]['id']
            with db_lock:
                if rows[0]['hips'] != 0:
                    return redirect(url_for('index'))
                
                highest = db.execute("SELECT hips FROM questions GROUP BY hips ORDER BY hips ASC")
                if len(highest) != 1:
                    highest = highest[1]['hips']
                else:
                    highest = highest[0]['hips']

                if highest == 0:
                    db.execute("UPDATE questions SET hips = ? WHERE team_id = ?", 500, tid)
                
                elif highest != 0:
                    highest -= 10
                    db.execute("UPDATE questions SET hips = ? WHERE team_id = ?", highest, tid)

                up_score = db.execute("SELECT (intro + wod + ten + ct + dsw + mm + bts + ftmt + va + hips + wita) AS sum_row FROM questions WHERE team_id = ?", tid)[0]['sum_row']
                db.execute("UPDATE teams SET score = ? WHERE id = ?", up_score, tid)

    elif name == "witaButton":
        answer = os.getenv("ANSWER_WITA")
        if answer == value:
            rows = db.execute("SELECT questions.wita, teams.id FROM teams LEFT JOIN questions ON teams.id = questions.team_id WHERE name = ?", session['team'])
            tid = rows[0]['id']
            with db_lock:
                if rows[0]['wita'] != 0:
                    return redirect(url_for('index'))
                
                highest = db.execute("SELECT wita FROM questions GROUP BY wita ORDER BY wita ASC")
                if len(highest) != 1:
                    highest = highest[1]['wita']
                else:
                    highest = highest[0]['wita']

                if highest == 0:
                    db.execute("UPDATE questions SET wita = ? WHERE team_id = ?", 500, tid)
                
                elif highest != 0:
                    highest -= 10
                    db.execute("UPDATE questions SET wita = ? WHERE team_id = ?", highest, tid)

                up_score = db.execute("SELECT (intro + wod + ten + ct + dsw + mm + bts + ftmt + va + hips + wita) AS sum_row FROM questions WHERE team_id = ?", tid)[0]['sum_row']
                db.execute("UPDATE teams SET score = ? WHERE id = ?", up_score, tid)
    
    return redirect(url_for('index'))

@app.route("/login", methods=['GET', 'POST'])
def login():
    # Remove the username, team, role, score from session
    session.pop('username', None)
    session.pop('team', None)
    session.pop('role', None)
    session.pop('score', None)

    if request.method == 'POST':
        username = escape(request.form['username'])
        password = escape(request.form['password'])

        # Sanitize input
        if (username == "" or password == ""):
            return redirect(url_for('login'))
        
        # Search database for username and password
        rows = db.execute("SELECT username, password from accounts WHERE username = ?", username)

        # Check if the query has the resulting username
        if len(rows) == 0:
            return redirect(url_for('login'))
        
        # Compare hashed_password with the one stored in the database
        hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf_8'), salt, pbkdf_iteration).hex()
        if hashed_password == rows[0]['password']:
            session['username'] = username
            
            # Check if user has a team
            rows = db.execute("SELECT team_id FROM accounts WHERE username = ?", username)
            if len(rows) == 0:
                return redirect(url_for('prompt'))
            
            # Query database for user entry
            rows = db.execute("SELECT * FROM accounts LEFT JOIN teams ON accounts.team_id = teams.id WHERE username = ?", username)[0]

            # Add team to session
            if rows['name'] != None:
                session['team'] = rows['name']
                

            # Add role to session
            if rows['role'] != None:
                session['role'] = rows['role']

            # Add score to session
            if rows['score'] != None:
                session['score'] = rows['score']

            return redirect(url_for('index'))
            

        # Wrong password
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route("/register", methods=['GET', 'POST'])
def register():   
    # Remove the username, team, role, score from session
    session.pop('username', None)
    session.pop('team', None)
    session.pop('role', None)
    session.pop('score', None)

    if request.method == 'POST' :
        username = escape(request.form['username'])
        password = escape(request.form['password'])
        
        # Sanitize input
        if (username == "" or password == ""):
            return redirect(url_for('register'))
        
        # Search database if username is unique
        rows = db.execute("SELECT username from accounts WHERE username = ?", username)

        if len(rows) != 0:
            return redirect(url_for('register'))
        
        # Add to database but hash the password first
        hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf_8'), salt, pbkdf_iteration).hex()
        rows = db.execute("INSERT INTO accounts (username, password) VALUES(?, ?)", username, hashed_password)
        
        # Add to session
        session['username'] = username

        return redirect(url_for('prompt'))

    return render_template('register.html')

@app.route("/prompt")
def prompt():    
    # Check if logged in
    if 'username' not in session:
        return redirect(url_for('login'))
    
    return render_template('prompt-team.html')

@app.route("/create", methods=['GET', 'POST'])
def create():    
    # Check if logged in
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Check if user has a team
    if 'team' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        team_name = escape(request.form['team_name'])

        # Make sure it is not empty
        if team_name == "":
            return redirect(url_for('create'))
        
        # Check database if team_name is taken
        rows = db.execute("SELECT name from teams WHERE name = ?", team_name)

        if len(rows) != 0:
            return redirect(url_for('create'))
        
        # Otherwise, update database 
        rows = db.execute("INSERT INTO teams (name, score) VALUES(?, ?)", team_name, 0)
        rows = db.execute("SELECT id FROM teams WHERE name = ?", team_name)
        add_ques = db.execute("INSERT INTO questions (team_id, intro, wod, ten, ct, dsw, mm, bts, ftmt, va, hips, wita) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rows[0]['id'], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        rows = db.execute("UPDATE accounts SET team_id = ?, role = ? WHERE username = ?", rows[0]['id'], escape("Leader"),  session['username'])
        

        # Add session
        session['team'] = team_name
        session['role'] = escape("Leader")
        session['score'] = 0

        return redirect(url_for('index'))

    return render_template('create.html')

@app.route("/join", methods=['GET', 'POST'])
def join():   
    # Check if logged in
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Check if user has a team
    if 'team' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        team_name = escape(request.form['team_name'])

        # Make sure it is not empty
        if team_name == "":
            return redirect(url_for('join'))
        
        # Check database if team_name exist
        rows = db.execute("SELECT name from teams WHERE name = ?", team_name)

        if len(rows) == 0:
            return redirect(url_for('join'))
        
        # Otherwise, update database 
        rows = db.execute("SELECT id FROM teams WHERE name = ?", team_name)
        rows = db.execute("UPDATE accounts SET team_id = ?, role = ? WHERE username = ?", rows[0]['id'], escape("Pending"), session['username'])
        
        # Add session
        session['team'] = team_name
        session['role'] = escape("Pending")
        tid = db.execute("SELECT team_id FROM accounts WHERE username = ?", session['username'])[0]['team_id']
        session['score'] = db.execute("SELECT score FROM teams WHERE id = ?", tid)[0]['score']

        return redirect(url_for('index'))

    return render_template('join.html')

@app.route("/team", methods=['GET', 'POST'])
def team():
    # Check if logged in
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Check if user does not have a team
    if 'team' not in session:        
        return redirect(url_for('prompt'))

    if request.method == 'POST':
        data = request.get_json()

        if session['role'] == "Leader":
            if data["action"] == "Leave":
                tid = db.execute("SELECT * FROM accounts WHERE accounts.username = ?", session['username'])[0]['team_id']
                rows = db.execute("UPDATE accounts SET role = ?, team_id = ? WHERE team_id = ?", None, None, tid)
                rows = db.execute("DELETE FROM teams WHERE id = ?", tid)
                session.pop('team', None)

            elif data["action"] in ["Kick", "Reject"]:  
                rows = db.execute("UPDATE accounts SET role = ?, team_id = ? WHERE username = ?", None, None, data["name"])

            elif data["action"] == "Promote":
                rows = db.execute("UPDATE accounts SET role = ? WHERE username = ?", "Leader", data["name"])
                rows = db.execute("UPDATE accounts SET role = ? WHERE username = ?", "Member", session['username'])
                session['role'] = "Member"

            elif data["action"] == "Accept":
                rows = db.execute("UPDATE accounts SET role = ? WHERE username = ?", "Member", data["name"])

        elif session['role'] == "Member":
            if data["action"] == "Leave":
                rows = db.execute("UPDATE accounts SET role = ?, team_id = ? WHERE username = ?", None, None, data["name"])
                session.pop('team', None)

            elif data["action"] == "Reject":  
                rows = db.execute("UPDATE accounts SET role = ?, team_id = ? WHERE username = ?", None, None, data["name"])

            elif data["action"] == "Accept":
                rows = db.execute("UPDATE accounts SET role = ? WHERE username = ?", "Member", data["name"])

        elif session['role'] == "Pending":
            if data["action"] == "Leave":
                rows = db.execute("UPDATE accounts SET role = ?, team_id = ? WHERE username = ?", None, None, data["name"])
                session.pop('team', None)

        return ('', 204)
    
    rows = db.execute("SELECT username, role, name  FROM accounts LEFT JOIN teams ON accounts.team_id = teams.id WHERE name = ?", session['team'])
    if rows[0]['name'] == None:
        return redirect(url_for("prompt"))
    return render_template('team.html', team_name=rows[0]['name'], item=rows, role=session['role'])

@app.route("/get_team", methods=['GET'])
def get_team():
    # Check if logged in
    if 'username' not in session:
        return redirect(url_for('login'))
    
    session.pop('team', None)
    session.pop('role', None)
    session.pop('score', None)

    rows = db.execute("SELECT role, name, score FROM accounts LEFT JOIN teams ON accounts.team_id = teams.id WHERE username = ?", session['username'])[0]    

    if rows['name'] == None:
        return redirect(url_for("prompt"))
    
    if rows['role'] != None:
        session['role'] = rows['role']
    
    if rows['name'] != None:
        session['team'] = rows['name']

    if rows['score'] != None:
        session['score'] = rows['score']

    rows = db.execute("SELECT username, role, name  FROM accounts LEFT JOIN teams ON accounts.team_id = teams.id WHERE name = ?", session['team'])
    return jsonify(render_template('get-team.html', team_name=rows[0]['name'], item=rows, role=session['role']))

@app.route("/leaderboards")
def leaderboards():    
    # Check if logged in
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Check if user does not have a team
    if 'team' not in session:
        return redirect(url_for('prompt'))

    rows = db.execute("SELECT name, score FROM teams ORDER BY score DESC LIMIT 15")
    team_standing = db.execute("SELECT Rank_no, name, score FROM (SELECT name, score, RANK() OVER(ORDER BY score DESC) AS Rank_no FROM teams) WHERE name = ?", session['team'])[0]
    return render_template('leaderboards.html', rows=rows, team_standing=team_standing)

@app.route("/get_leaderboards")
def get_leaderboards():
    # Check if logged in
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Check if user does not have a team
    if 'team' not in session:
        return redirect(url_for('prompt'))

    rows = db.execute("SELECT name, score FROM teams ORDER BY score DESC LIMIT 15")
    team_standing = db.execute("SELECT Rank_no, name, score FROM (SELECT name, score, RANK() OVER(ORDER BY score DESC) AS Rank_no FROM teams) WHERE name = ?", session['team'])[0]
    return jsonify(render_template('get-leaderboards.html', rows=rows, team_standing=team_standing))

@app.route("/garage")
def garage():  
    # Check if logged in
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Check if user does not have a team
    if 'team' not in session:
        return redirect(url_for('prompt'))
      
    return render_template('garage.html')


@app.route("/bank")
def bank():    
    # Check if logged in
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Check if user does not have a team
    if 'team' not in session:
        return redirect(url_for('prompt'))
    
    return render_template('bank.html')

@app.route("/bank", methods=['POST'])
@limiter.limit("1 per 5 seconds")
def post_bank():    
    # Check if logged in
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Check if user does not have a team
    if 'team' not in session:
        return redirect(url_for('prompt'))
    
    if request.method == 'POST':
        pin = escape(request.form['pin'])
        cardNo = escape(request.form['cardNo'])
        secret_pin = os.getenv("SECRET_PIN")
        if pin == secret_pin and cardNo == "374245455400126":
            return render_template('bank-home.html')
        
    return render_template('bank.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
