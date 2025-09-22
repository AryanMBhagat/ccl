from flask import Flask, render_template, request, redirect, url_for, session, flash,jsonify, send_from_directory, send_file 
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os
from werkzeug.utils import secure_filename
import mimetypes

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Needed for sessions

# Initialize DB (run once)
def init_db():
    with sqlite3.connect('users.db') as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
                          id INTEGER PRIMARY KEY AUTOINCREMENT,
                          email TEXT UNIQUE NOT NULL,
                          password TEXT NOT NULL
                      )''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS calculation_entries (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               sample_id TEXT NOT NULL,
               calc_type TEXT NOT NULL,
               param TEXT NOT NULL,
               value REAL,
               result REAL,
               timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        conn.execute('''
            CREATE TABLE IF NOT EXISTS detailed_calculations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sample_id TEXT NOT NULL,
                calc_name TEXT NOT NULL,
                values_json TEXT,
                result REAL,
                date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        conn.execute('''
            CREATE TABLE IF NOT EXISTS job_roles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                role TEXT NOT NULL
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS equipments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                quantity INTEGER DEFAULT 1
            )
        ''')


@app.route('/')
def lims():
    return render_template('lims.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password_input = request.form['password']

        with sqlite3.connect('users.db') as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT password FROM users WHERE email=?", (email,))
            user = cursor.fetchone()

        if user and check_password_hash(user[0], password_input):
            session['user'] = email
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password')

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password_input = request.form['password']
        hashed_password = generate_password_hash(password_input)

        try:
            with sqlite3.connect('users.db') as conn:
                conn.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, hashed_password))
                conn.commit()
            flash('Account created! Please log in.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists.')

    return render_template('signup.html')

@app.route('/save-sample', methods=['POST'])
def save_sample():
    data = request.get_json()
    sample_id = data.get('sample_id')
    calc_type = data.get('calc_type')  # e.g., "Moisture", "Ash"
    values = data.get('values', {})    # e.g., { "m1": 12.5, "m2": 11.2 }
    result = data.get('result')        # final calculated result

    if not sample_id or not calc_type or not values:
        return jsonify({"status": "error", "message": "Missing data"}), 400

    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()

        # Delete previous entries for this sample+calc_type
        cursor.execute(
            "DELETE FROM calculation_entries WHERE sample_id = ? AND calc_type = ?",
            (sample_id, calc_type)
        )

        # Insert new values
        for idx, (param, val) in enumerate(values.items()):
            cursor.execute('''
                INSERT INTO calculation_entries (sample_id, calc_type, param, value, result)
                VALUES (?, ?, ?, ?, ?)
            ''', (sample_id, calc_type, param, val, result if idx == 0 else None))

        conn.commit()

    return jsonify({"status": "success"})

@app.route('/save-detailed', methods=['POST'])
def save_detailed():
    import json
    data = request.get_json()

    sample_id = data.get('sample_id')
    calc_name = data.get('calc_name')
    values = json.dumps(data.get('values'))  # {"m1":..., "m2":...}
    result = data.get('result')

    valid_calc_names = {"ash", "mos", "vm", "fc"}
    if calc_name not in valid_calc_names:
        return jsonify({"status": "error", "message": f"Invalid calculation name: {calc_name}"}), 400


    if not sample_id or not calc_name:
        return jsonify({"status": "error", "message": "Missing fields"}), 400

    with sqlite3.connect('users.db') as conn:
        conn.execute('''
            INSERT INTO detailed_calculations (sample_id, calc_name, values_json, result)
            VALUES (?, ?, ?, ?)
        ''', (sample_id, calc_name, values, result))
        conn.commit()

    return jsonify({"status": "success"})



@app.route('/get-sample/<sample_id>')
def get_sample(sample_id):
    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT calc_type, param, value, result
            FROM calculation_entries
            WHERE sample_id = ?
        ''', (sample_id,))
        rows = cursor.fetchall()

    grouped = {}
    for calc_type, param, value, result in rows:
        if calc_type not in grouped:
            grouped[calc_type] = {"name": calc_type, "values": {}, "result": None}
        grouped[calc_type]["values"][param] = value
        if result is not None:
            grouped[calc_type]["result"] = result

    response = {
        "sample_id": sample_id,
        "calculations": list(grouped.values())
    }
    return jsonify(response)

@app.route('/get-all-samples')
def get_all_samples():
    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT sample_id, calculation_type, m1, m2, m3, mo0, result, date
            FROM sample_calculations
        ''')
        rows = cursor.fetchall()

    samples = {}
    for row in rows:
        sid = row[0]
        calc = row[1]
        if sid not in samples:
            samples[sid] = {}
        samples[sid][calc] = {
            "m1": row[2], "m2": row[3], "m3": row[4],
            "mo0": row[5], "result": row[6], "date": row[7]
        }

    return jsonify(samples)

@app.route('/get-detailed/<sample_id>')
def get_detailed(sample_id):
    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT calc_name, values_json, result, date
            FROM detailed_calculations
            WHERE sample_id = ?
        ''', (sample_id,))
        rows = cursor.fetchall()

    import json
    return jsonify([
        {
            "calc_name": row[0],
            "values": json.loads(row[1]),
            "result": row[2],
            "date": row[3]
        } for row in rows
    ])



@app.route('/get-jobs')
def get_jobs():
    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, role FROM job_roles")
        jobs = cursor.fetchall()
    return jsonify([{"id": row[0], "name": row[1], "role": row[2]} for row in jobs])

@app.route('/add-job', methods=['POST'])
def add_job():
    data = request.get_json()
    name = data.get('name')
    role = data.get('role')
    if not name or not role:
        return jsonify({"status": "error", "message": "Missing fields"}), 400

    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO job_roles (name, role) VALUES (?, ?)", (name, role))
        conn.commit()

    return jsonify({"status": "success"})

@app.route('/update-job/<int:job_id>', methods=['POST'])
def update_job(job_id):
    data = request.get_json()
    name = data.get('name')
    role = data.get('role')

    if not name or not role:
        return jsonify({"status": "error", "message": "Missing fields"}), 400

    with sqlite3.connect('users.db') as conn:
        conn.execute("UPDATE job_roles SET name = ?, role = ? WHERE id = ?", (name, role, job_id))
        conn.commit()

    return jsonify({"status": "success"})
 
@app.route('/delete-job/<int:job_id>', methods=['DELETE'])
def delete_job(job_id):
    with sqlite3.connect('users.db') as conn:
        conn.execute("DELETE FROM job_roles WHERE id = ?", (job_id,))
        conn.commit()
    return jsonify({"status": "success"})

@app.route('/get-equipments')
def get_equipments():
    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, description, quantity FROM equipments")
        rows = cursor.fetchall()
    return jsonify([{"id": r[0], "name": r[1], "desc": r[2], "qty": r[3]} for r in rows])

@app.route('/add-equipment', methods=['POST'])
def add_equipment():
    data = request.get_json()
    name = data.get('name')
    desc = data.get('desc') or '—'
    qty = data.get('qty', 1)

    if not name:
        return jsonify({"status": "error", "message": "Missing name"}), 400

    with sqlite3.connect('users.db') as conn:
        conn.execute("INSERT INTO equipments (name, description, quantity) VALUES (?, ?, ?)",
                     (name, desc, qty))
        conn.commit()

    return jsonify({"status": "success"})

@app.route('/update-equipment/<int:equip_id>', methods=['POST'])
def update_equipment(equip_id):
    data = request.get_json()
    new_qty = data.get('qty')

    if new_qty is None or new_qty < 1:
        return jsonify({"status": "error", "message": "Invalid quantity"}), 400

    with sqlite3.connect('users.db') as conn:
        conn.execute("UPDATE equipments SET quantity = ? WHERE id = ?", (new_qty, equip_id))
        conn.commit()

    return jsonify({"status": "success"})

@app.route('/delete-equipment/<int:equip_id>', methods=['DELETE'])
def delete_equipment(equip_id):
    with sqlite3.connect('users.db') as conn:
        conn.execute("DELETE FROM equipments WHERE id = ?", (equip_id,))
        conn.commit()
    return jsonify({"status": "success"})




@app.route('/home')
def home():
    if 'user' in session:
        return render_template('home.html', username=session['user'])
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('lims'))

@app.route('/page/<page_name>')
def render_dynamic_page(page_name):
    try:
        return render_template(f'{page_name}.html')
    except:
        return "404 - Page not found", 404


UPLOAD_FOLDER = os.path.join('static', 'uploads')  # ✅ CORRECT: returns a string
ALLOWED_EXTENSIONS = {'pdf', 'docx'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/quality-manual', methods=['GET', 'POST'])
def quality_manual():
    folder = app.config['UPLOAD_FOLDER']
    files = os.listdir(folder)
    return render_template('quality_manual.html', files=files)

@app.route('/upload-manual', methods=['POST'])
def upload_manual():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(url_for('quality_manual'))

    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('quality_manual'))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)  # must return a string
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(upload_path)

        flash('File uploaded successfully!')
    else:
        flash('Invalid file type. Only PDF and DOCX allowed.')

    return redirect(url_for('quality_manual'))


@app.route('/delete-manual/<filename>', methods=['POST'])
def delete_manual(filename):
    path = os.path.join(UPLOAD_FOLDER, filename)
    if os.path.exists(path):
        os.remove(path)
        flash('File deleted.')
    else:
        flash('File not found.')
    return redirect(url_for('quality_manual'))

@app.route('/view-manual/<filename>')
def view_manual(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(file_path):
        return "File not found", 404
    return render_template('view_file.html', filename=filename)

@app.route('/uploads/<filename>')
def serve_manual_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    mimetype = mimetypes.guess_type(file_path)[0]
    return send_file(file_path, mimetype=mimetype, as_attachment=False)



if __name__ == '__main__':
    init_db()
    app.run(debug=True)
