import hashlib
from datetime import datetime, timedelta, date
from functools import wraps

import jwt
import psycopg2
from flask import Flask, request, render_template, redirect, jsonify, session, flash

app = Flask(__name__)
app.secret_key = '8sJqMOWkUCy2tW6Xiubx'
salt = 'VsikgpaJavBH_v8OvEl'
exp_time = 15

JWT_SECRET = app.secret_key
JWT_ALGORITHM = 'HS256'
JWT_EXP_DELTA_SECONDS = 360

conn = psycopg2.connect(database="medical_center", user="postgres", password="postgres", host="localhost", port="5433")

# diana.konontseva@mail.ru diana123
# doctor: diankabelarus@gmail.com vlad1234
# doctor: mashkova@gmail.com mashkova123
def contains_forbidden_chars(string):
    forbidden_chars = [' ', '$', '#', '<', '>', '&', '^', '*', '-', '!', '№', '%', ':', ';', '?', '/', '+', '=',
                       '(', ')', '`', '~', '|', ',']
    for char in forbidden_chars:
        if char in string:
            return True
    return False


def password_forbidden_chars(string):
    forbidden_chars = [' ', '?', '#', '<', '>', '%', '@', '/']
    for char in forbidden_chars:
        if char in string:
            return True
    return False


def token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')  # Извлекаем токен из куки

        if not token:
            return render_template('auth.html',
                                   error_message="You need to log in to get access.")  # Перенаправляем на страницу логина при отсутствии токена

        try:
            # Проверяем и декодируем токен
            jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except jwt.ExpiredSignatureError:
            return render_template('auth.html', error_message="Your session is ended. Please, update..")
        except jwt.InvalidTokenError:
            return render_template('auth.html', error_message="Error. Please log in to get access.")
        return func(*args, **kwargs)

    decorated.__name__ = func.__name__
    return decorated


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect('/login')
        return func(*args, **kwargs)

    return wrapper


def role_required(required_roles):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if 'user_role' not in session:
                flash("You must be logged in to access this page.", "error")
                return redirect('/error')
            if session['user_role'] not in required_roles:
                flash("You do not have permission to access this page.", "error")
                return redirect('/error')
            return func(*args, **kwargs)

        return wrapper

    return decorator


@app.route('/', methods=['GET', 'POST'])
def index():
    return redirect('/login')

@app.route('/error', methods=['GET', 'POST'])
def error():
    return render_template('error.html')

@app.route('/registration', methods=['GET', 'POST'])
def registration():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        repeat_password = request.form['repeat_password']

        if not email or not password:
            return render_template('registration.html', error_message="Please!!! Fill the gaps.")

        if len(password) < 8:
            return render_template('registration.html', error_message="Password should be at least 8 characters long.")

        if password != repeat_password:
            return render_template('registration.html', error_message="Passwords do not match.")

        if contains_forbidden_chars(email) or password_forbidden_chars(password):
            return render_template('registration.html',
                                   error_message="Username and password shouldn't contain specific symbols.")

        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE login = %s", (email,))
        result = cursor.fetchone()
        cursor.close()

        if result[0] > 0:
            return render_template('registration.html',
                                   error_message="User with this email already exists.")

        hashed_password = hashlib.sha256((password + salt).encode()).hexdigest()

        cursor = conn.cursor()
        cursor.execute("INSERT INTO users(login, password, role_id) VALUES(%s, %s, %s)", (email, hashed_password, 1), )
        conn.commit()
        cursor.close()
        return redirect('/login')
    else:
        return render_template('registration.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        cursor = conn.cursor()
        cursor.execute("SELECT users._id, users.password, role.role FROM users JOIN role "
                       "ON users.role_id = role._id  WHERE login = %s", (email,))
        result = cursor.fetchone()
        cursor.close()

        if result is None:
            return render_template('auth.html', error_message="Incorrect login. Please try again.")

        stored_password = result[1]
        decrypted_password = hashlib.sha256((password + salt).encode()).hexdigest()

        if decrypted_password == stored_password:

            session['user_id'] = result[0]
            session['user_email'] = result[1]
            session['user_role'] = result[2]
            if session['user_role'] == 'patient':
                response = redirect('/patientDashboard')
            if session['user_role'] == 'doctor':
                response = redirect('/doctor/dashboard')
            if session['user_role'] == 'admin':
                response = redirect('/admin/dashboard')

            return response
        else:
            return render_template('auth.html', error_message="Incorrect password. Please try again.")
    else:
        return render_template('auth.html')


@app.route('/patientDashboard', methods=['GET', 'POST'])
@login_required
@role_required(['patient'])
def patient_dashboard():
    user_id = session.get('user_id')
    cursor = conn.cursor()
    cursor.execute("SELECT patients._id FROM patients WHERE patients.user_id = %s", (user_id,))
    patient_id = cursor.fetchone()

    cursor.execute("SELECT patients.first_name, patients.last_name"
                   " FROM patients WHERE patients.user_id = %s", (user_id,))
    current_user = cursor.fetchone()

    if request.method == 'POST':
        action = request.form.get('action')
        appointment_id = request.form.get('appointment_id')
        if action == 'cancel':
            cursor.execute("""
                DELETE FROM talons
                WHERE _id = %s AND patient_id = %s
            """, (appointment_id, patient_id))
        conn.commit()

    cursor.execute("""
        SELECT MIN(date) AS next_appointment
        FROM talons
        WHERE patient_id = %s AND date >= CURRENT_DATE
    """, (patient_id,))
    next_appointment = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) AS medical_records
        FROM talons 
        WHERE patient_id = %s
    """, (patient_id,))
    medical_records = cursor.fetchone()[0]

    cursor.execute("""
        SELECT EXTRACT(MONTH FROM date) AS month, COUNT(*) AS count
        FROM talons
        WHERE patient_id = %s
        GROUP BY month
        ORDER BY month
    """, (patient_id,))
    visits_by_month = cursor.fetchall()
    visits_by_month_full = [0] * 12

    for month, count in visits_by_month:
        visits_by_month_full[int(month) - 1] = count

    cursor.execute("""
        SELECT departments.department, COUNT(*) AS count
        FROM talons
        JOIN doctors ON talons.doctor_id = doctors._id
        JOIN departments ON doctors.department_id = departments._id
        WHERE talons.patient_id = %s
        GROUP BY departments.department
    """, (patient_id,))
    visits_by_department = cursor.fetchall()

    cursor.execute("""
        SELECT doctors.first_name, doctors.last_name, departments.department, talons.date, talons.time, talons.status, talons._id 
        FROM talons
        JOIN doctors ON talons.doctor_id = doctors._id
        JOIN departments ON doctors.department_id = departments._id
        WHERE patient_id = %s AND date >= CURRENT_DATE
        ORDER BY date, time
        LIMIT 5
    """, (patient_id,))
    recent_appointments = cursor.fetchall()

    cursor.execute("""
        SELECT doctors.first_name, doctors.last_name, departments.department, talons.date, talons.time, talons.status
        FROM talons
        JOIN doctors ON talons.doctor_id = doctors._id
        JOIN departments ON doctors.department_id = departments._id
        WHERE patient_id = %s AND date < CURRENT_DATE
        ORDER BY date DESC, time DESC
    """, (patient_id,))
    appointment_history = cursor.fetchall()

    cursor.close()

    return render_template(
        'patients/dashboard.html',
        current_user=current_user,
        next_appointment=next_appointment,
        medical_records=medical_records,
        visits_by_month=visits_by_month_full,
        visits_by_department=visits_by_department,
        recent_appointments=recent_appointments,
        appointment_history=appointment_history,
    )


@app.route('/patientProfile', methods=['GET', 'POST'])
@login_required
@role_required(['patient'])
def patient_profile():
    cursor = conn.cursor()

    if request.method == 'GET':
        cursor.execute("SELECT first_name, last_name, second_name, phone_number, email, b_day, gender, country, "
                       "city, street, house, flat, addresses._id  from patients join addresses on patients.address_id = addresses._id "
                       "where user_id=%s", (session.get('user_id'),))
        result = cursor.fetchone()
        print(result)
        return render_template('patients/profile.html', user_profile=result)

    elif request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        second_name = request.form.get('second_name')
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')
        gender = request.form.get('gender')
        date_of_birth = request.form.get('date_of_birth')

        cursor.execute("""
                UPDATE patients
                SET first_name = %s, last_name = %s, second_name = %s, email = %s,
                    phone_number = %s, gender = %s, b_day = %s
                WHERE user_id = %s
            """, (
            str(first_name), str(last_name), str(second_name), str(email), str(phone_number), str(gender),
            date_of_birth,
            str(session.get('user_id'))))
        conn.commit()

        cursor.close()
        return redirect('/patientProfile')


@app.route('/patientProfileAddress', methods=['POST'])
@login_required
@role_required(['patient'])
def patient_profile_address():
    cursor = conn.cursor()
    if request.method == 'POST':
        country = request.form.get('country')
        city = request.form.get('city')
        street = request.form.get('street')
        house = request.form.get('house')
        flat = request.form.get('flat')
        address_id = request.form.get('address_id')

        cursor.execute("""
                UPDATE addresses
                SET country = %s, city = %s, street = %s, house = %s, flat = %s
                WHERE _id=%s
            """, (str(country), str(city), str(street), str(house), str(flat), address_id))
        conn.commit()

        cursor.close()
        return redirect('/patientProfile')


@app.route('/patientChangePassword', methods=['POST'])
@login_required
@role_required(['patient'])
def patient_change_password():
    if request.method == 'POST':
        old_password = request.form.get('old-password')
        new_password = request.form.get('new-password')
        repeat_password = request.form.get('repeat-password')

        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE _id = %s", (str(session.get('user_id')),))
        result = cursor.fetchone()

        stored_password = result[0]
        decrypted_password = hashlib.sha256((old_password + salt).encode()).hexdigest()

        if decrypted_password != stored_password:
            return redirect('/patientProfile')

        if new_password != repeat_password:
            return redirect('/patientProfile')

        encrypted_new = hashlib.sha256((new_password + salt).encode()).hexdigest()

        cursor.execute("""
                        UPDATE users
                        SET password = %s WHERE _id=%s
                    """, (str(encrypted_new), str(session.get('user_id'))))
        conn.commit()
        cursor.close()

    return redirect('/patientProfile')


@app.route('/myMedicalCard', methods=['GET', 'POST'])
@login_required
@role_required(['patient'])
def myMedicalCard():
    if request.method == 'POST':
        search_query = request.form.get('search_query', '').strip()
        search_query = f"%{search_query}%"
        user_id = session.get('user_id')
        cursor = conn.cursor()
        cursor.execute("""
                SELECT doctors.first_name, doctors.second_name, medical_card.date, medical_card._id
                FROM medical_card
                JOIN patients ON medical_card.patient_id = patients._id
                JOIN doctors ON medical_card.doctor_id = doctors._id
                WHERE patients.user_id = %s AND (doctors.first_name ILIKE %s OR doctors.second_name ILIKE %s);
            """, (user_id, search_query, search_query))
        search = cursor.fetchall()
        cursor.close()
        print(search)
        return render_template('patients/medicalCard.html', medicalCard=search)

    if (request.method == 'GET'):
        cursor = conn.cursor()
        cursor.execute("""SELECT doctors.first_name, doctors.second_name, medical_card.date, medical_card._id FROM medical_card 
                                join patients on medical_card.patient_id=patients._id 
                                join doctors on medical_card.doctor_id = doctors._id
                                where patients.user_id=%s""", (str(session.get('user_id')),))
        result = cursor.fetchall()
        cursor.close()
        return render_template('patients/medicalCard.html', medicalCard=result)


@app.route('/medicalRecord/<int:record_id>', methods=['GET'])
@login_required
@role_required(['patient'])
def medical_record(record_id):
    cursor = conn.cursor()
    cursor.execute("""
        SELECT mc.*, 
               p.first_name || ' ' || p.last_name AS patient_name, p.b_day,
               d.first_name || ' ' || d.last_name AS doctor_name
        FROM medical_card mc
        JOIN patients p ON mc.patient_id = p._id
        JOIN doctors d ON mc.doctor_id = d._id
        WHERE mc._id = %s""", str(record_id))
    record = cursor.fetchone()
    conn.close()

    return render_template('patients/medicaCardNote.html', record=record)


@app.route('/searchMedNote', methods=['GET', 'POST'])
@login_required
@role_required(['patient'])
def searchMedNote():
    search_query = request.form.get('search_query')
    if (request.method == 'POST'):
        cursor = conn.cursor()
        print(cursor.execute("""SELECT doctors.first_name, doctors.second_name, medical_card.date, medical_card._id
                                FROM medical_card
                                JOIN patients ON medical_card.patient_id = patients._id
                                JOIN doctors ON medical_card.doctor_id = doctors._id
                                WHERE patients.user_id = %s AND (doctors.first_name ILIKE %s OR doctors.second_name ILIKE %s 
                                OR doctors.last_name ILIKE %s);
                                """,
                             (str(session.get('user_id')), search_query, search_query)))
        search = cursor.fetchall()
        cursor.close()
    return render_template('patients/medicalCard.html', medicalCard=search)


@app.route('/findAppointment', methods=['GET'])
@login_required
@role_required(['patient'])
def find_appointment():
    cursor = conn.cursor()

    cursor.execute("SELECT _id, department FROM departments ORDER BY department ASC")
    departments = cursor.fetchall()

    requested_date = request.args.get('date', date.today().isoformat())
    department = request.args.get('department', '')
    doctor_search = request.args.get('doctor_search', '')

    day_of_week = datetime.strptime(requested_date, '%Y-%m-%d').isoweekday()

    query = """
        SELECT doctors._id, doctors.first_name, doctors.last_name, doctors.phone_number, departments.department
        FROM doctors
        JOIN departments ON doctors.department_id = departments._id
        JOIN schedules ON doctors._id = schedules.doctor_id
        WHERE schedules.day_of_week = %s
    """
    params = [day_of_week]

    if department:
        query += " AND departments.department ILIKE %s"
        params.append(f"%{department}%")

    if doctor_search:
        query += """
            AND (doctors.first_name ILIKE %s 
            OR doctors.last_name ILIKE %s 
            OR doctors.second_name ILIKE %s)
        """
        params.extend([f"%{doctor_search}%"] * 3)

    cursor.execute(query, params)
    doctors = cursor.fetchall()
    cursor.close()

    return render_template(
        'patients/findAppointment.html',
        date=requested_date,
        doctor_list=doctors,
        departments=departments
    )


@app.route('/findAppointment/slots', methods=['GET'])
@login_required
@role_required(['patient'])
def get_available_slots():
    doctor_id = request.args.get('doctor_id')
    date = request.args.get('date', datetime.now().strftime('%Y-%m-%d'))
    day_of_week = datetime.strptime(date, '%Y-%m-%d').isoweekday()

    cursor = conn.cursor()

    cursor.execute("""
        SELECT shifts.start_time, shifts.end_time 
        FROM shifts 
        JOIN schedules ON shifts._id = schedules.shift_id
        WHERE schedules.doctor_id = %s AND schedules.day_of_week = %s
    """, (doctor_id, day_of_week))
    shifts = cursor.fetchall()

    cursor.execute("""
        SELECT time FROM talons
        WHERE doctor_id = %s AND date = %s
    """, (doctor_id, date))
    booked_slots = {row[0] for row in cursor.fetchall()}

    cursor.close()

    available_slots = []
    for start_time, end_time in shifts:
        current_time = datetime.combine(datetime.today(), start_time)
        end_time_dt = datetime.combine(datetime.today(), end_time)

        while current_time < end_time_dt:
            slot_time = current_time.strftime('%H:%M')
            if slot_time not in booked_slots:
                available_slots.append(slot_time)
            current_time += timedelta(minutes=30)

    return jsonify({"available_slots": available_slots})


@app.route('/bookAppointment', methods=['POST'])
@login_required
@role_required(['patient'])
def book_appointment():
    data = request.get_json()
    doctor_id = data.get('doctor_id')
    date = data.get('date')
    start_time = data.get('time')
    user_id = session.get('user_id')
    cursor = conn.cursor()

    cursor.execute("SELECT patients._id FROM patients WHERE patients.user_id = %s", (user_id,))
    patient_id = cursor.fetchone()
    print("bookAppointment " + str(patient_id))

    cursor.execute("""
        INSERT INTO talons (doctor_id, patient_id, date, time, status)
        VALUES (%s, %s, %s, %s, 'pending')
    """, (doctor_id, patient_id[0], date, start_time))
    conn.commit()
    cursor.close()

    return jsonify({"message": "Appointment booked successfully!"})


@app.route('/doctor/dashboard', methods=['GET', 'POST'])
@login_required
@role_required(['doctor'])
def doctor_dashboard():
    cursor = conn.cursor()
    cursor.execute("""SELECT _id FROM doctors WHERE user_id = %s""", (str(session.get('user_id')),))
    doctor_id = cursor.fetchone()[0]
    today = datetime.now().date()

    if request.method == 'POST':
        action = request.form.get('action')
        appointment_id = request.form.get('appointment_id')
        if action == 'accept':
            cursor.execute("""
                UPDATE talons
                SET status = 'confirmed'
                WHERE _id = %s AND doctor_id = %s
            """, (appointment_id, doctor_id))
        elif action == 'cancel':
            cursor.execute("""
                UPDATE talons
                SET status = 'declined'
                WHERE _id = %s AND doctor_id = %s
            """, (appointment_id, doctor_id))
        conn.commit()

    cursor.execute("""
        SELECT COUNT(DISTINCT patient_id)
        FROM talons
        WHERE doctor_id = %s
    """, (doctor_id,))
    total_patients = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM talons
        WHERE doctor_id = %s AND date = %s
    """, (doctor_id, today))
    today_patients = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM talons
        WHERE doctor_id = %s
    """, (doctor_id,))
    total_appointments = cursor.fetchone()[0]

    cursor.execute("""
        SELECT a._id, p.first_name, p.last_name, a.date, a.time, a.purpose, a.status
        FROM talons a
        JOIN patients p ON a.patient_id = p._id
        WHERE a.doctor_id = %s AND a.date >= %s AND a.status != 'declined'
        ORDER BY a.date, a.time
    """, (doctor_id, today))
    upcoming_appointments = cursor.fetchall()

    cursor.execute("""
        SELECT a._id, p.first_name, p.last_name, a.time, a.purpose, a.status, a.patient_id
        FROM talons a
        JOIN patients p ON a.patient_id = p._id
        WHERE a.doctor_id = %s AND a.date = %s AND a.status != 'declined'
        ORDER BY a.time
    """, (doctor_id, today))
    today_appointments = cursor.fetchall()

    cursor.close()

    return render_template('doctors/dashboard.html',
                           total_patients=total_patients,
                           today_patients=today_patients,
                           total_appointments=total_appointments,
                           upcoming_appointments=upcoming_appointments,
                           today_appointments=today_appointments)


@app.route('/doctor/add_note/<int:patient_id>', methods=['GET', 'POST'])
@login_required
@role_required(['doctor'])
def add_note(patient_id):
    cursor = conn.cursor()
    # Получение данных врача
    cursor.execute(""" SELECT _id, first_name, last_name FROM doctors WHERE user_id = %s""",
                   (str(session.get('user_id')),))
    doctor = cursor.fetchone()

    if request.method == 'POST':
        # Получение данных из формы
        date = request.form.get('date')
        symptoms = request.form.get('symptoms')
        results = request.form.get('results')
        diagnosis = request.form.get('diagnosis')

        cursor.execute("""
            INSERT INTO medical_card (patient_id, doctor_id, date, complaints, wellness_check, disease)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (patient_id, doctor[0], date, symptoms, results, diagnosis))
        conn.commit()
        cursor.close()

        return redirect('/doctor/dashboard')

    cursor.execute("""
        SELECT first_name, last_name FROM patients WHERE _id = %s
    """, (patient_id,))
    patient = cursor.fetchone()

    cursor.close()

    return render_template('doctors/notesPatient.html', patient=patient, doctor=doctor, patient_id=patient_id)


@app.route('/doctor/patientsCards', methods=['GET', 'POST'])
@login_required
@role_required(['doctor'])
def patientsCards():
    cursor = conn.cursor()
    if request.method == 'POST':
        search_query = request.form.get('search_query', '').strip()
        search_query = f"%{search_query}%"
        cursor.execute("""
                SELECT patients.last_name, patients.first_name, medical_card.date, medical_card._id
                FROM medical_card
                JOIN patients ON medical_card.patient_id = patients._id
                JOIN doctors ON medical_card.doctor_id = doctors._id
                WHERE doctors.user_id = %s AND (patients.first_name ILIKE %s OR patients.second_name ILIKE %s);
            """, (session.get('user_id'), search_query, search_query))
        search = cursor.fetchall()
        print(search)
        return render_template('doctors/patientsCards.html', medicalCard=search)

    if (request.method == 'GET'):
        cursor.execute("""SELECT patients.last_name, patients.first_name, medical_card.date, medical_card._id FROM medical_card 
                                join patients on medical_card.patient_id=patients._id 
                                join doctors on medical_card.doctor_id = doctors._id
                                where doctors.user_id=%s ORDER BY medical_card.date DESC """,
                       (session.get('user_id'),))
        result = cursor.fetchall()
        cursor.close()
        return render_template('doctors/patientsCards.html', medicalCard=result)


@app.route('/doctor/medicalRecord/<int:record_id>', methods=['GET'])
@login_required
@role_required(['doctor'])
def medical_record_doctor(record_id):
    cursor = conn.cursor()
    cursor.execute("""
        SELECT mc.*, 
               p.first_name || ' ' || p.last_name AS patient_name, p.b_day,
               d.first_name || ' ' || d.last_name AS doctor_name
        FROM medical_card mc
        JOIN patients p ON mc.patient_id = p._id
        JOIN doctors d ON mc.doctor_id = d._id
        WHERE mc._id = %s""", (record_id,))
    record = cursor.fetchone()
    cursor.close()

    return render_template('doctors/medicalCard.html', record=record)


@app.route('/doctor/myLeaves', methods=['GET', 'POST'])
@login_required
@role_required(['doctor'])
def doctor_myLeaves():
    cursor = conn.cursor()
    current_date = datetime.now().strftime('%Y-%m-%d')

    cursor.execute("""
        SELECT _id FROM doctors WHERE user_id = %s
    """, (session.get('user_id'),))
    doctor_id = cursor.fetchone()[0]

    if request.method == 'GET':
        cursor.execute("""
            SELECT leave_type, from_date, to_date, reason, status, 
                   (to_date - from_date + 1) AS days_count, _id
            FROM doctorLeaves
            WHERE doctor_id = %s
            ORDER BY from_date DESC
        """, (doctor_id,))
        doctor_leaves = cursor.fetchall()
        cursor.close()
        return render_template('doctors/myLeaves.html', doctorLeaves=doctor_leaves, current_date=current_date)

    if request.method == 'POST':
        search_query = request.form.get('search_query', '').strip()
        leave_type = request.form.get('leave_type', '').strip()
        status = request.form.get('status', '').strip()
        from_date = request.form.get('from_date', current_date)
        to_date = request.form.get('to_date', current_date)

        query = """
             SELECT leave_type, from_date, to_date, reason, status, 
                    (to_date - from_date + 1) AS days_count, doctorLeaves._id
             FROM doctorLeaves
             WHERE doctor_id = %s
         """
        params = [doctor_id]

        if search_query:
            query += """
                 AND (leave_type ILIKE %s OR reason ILIKE %s)
             """
            params.extend([f"%{search_query}%", f"%{search_query}%"])

        if leave_type:
            query += " AND leave_type = %s"
            params.append(leave_type)

        if status:
            query += " AND status = %s"
            params.append(status)

        if from_date:
            query += " AND from_date >= %s "
            params.append(from_date)

        if to_date:
            query += " AND to_date <= %s"
            params.append(to_date)

        # Выполнение запроса и возврат результатов
        print(query, params)  # Для отладки
        cursor.execute(query, params)
        doctor_leaves = cursor.fetchall()
        cursor.close()

        return render_template('doctors/myLeaves.html', doctorLeaves=doctor_leaves, current_date=current_date)


@app.route('/doctor/addLeave', methods=['GET', 'POST'])
@app.route('/doctor/addLeave/<int:leave_id>', methods=['GET', 'POST'])
@login_required
@role_required(['doctor'])
def doctor_addLeave(leave_id=None):
    cursor = conn.cursor()
    cursor.execute("""
        SELECT _id FROM doctors WHERE user_id = %s
    """, (session.get('user_id'),))
    doctor_id = cursor.fetchone()[0]

    if request.method == 'GET':
        if leave_id:
            cursor.execute("""
                SELECT leave_type, from_date, to_date, reason, status, doctors.last_name, doctors.first_name, doctors.second_name 
                FROM doctorleaves JOIN doctors on doctorleaves.doctor_id = doctors._id 
                WHERE doctorleaves._id = %s AND doctorleaves.doctor_id = %s
            """, (leave_id, doctor_id))
            leave_data = cursor.fetchone()
            cursor.close()

            if leave_data:
                return render_template('doctors/editLeaves.html', leave=leave_data, leave_id=leave_id)
            else:
                return "Leave not found or unauthorized access.", 404
        else:
            empty_leave_data = {
                'leave_type': '',
                'from_date': '',
                'to_date': '',
                'reason': '',
                'status': 'Pending',
            }
            return render_template('doctors/editLeaves.html', leave=empty_leave_data)

    if request.method == 'POST':
        leave_type = request.form.get('leave_type')
        from_date = request.form.get('from_date')
        to_date = request.form.get('to_date')
        reason = request.form.get('notes', '').strip()

        if leave_id:
            cursor.execute("""
                UPDATE doctorleaves
                SET leave_type = %s, from_date = %s, to_date = %s, reason = %s 
                WHERE _id = %s AND doctor_id = %s
            """, (leave_type, from_date, to_date, reason, leave_id, doctor_id))
        else:
            cursor.execute("""
                INSERT INTO doctorleaves (doctor_id, leave_type, from_date, to_date, reason, status)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (doctor_id, leave_type, from_date, to_date, reason, 'Pending'))

        conn.commit()
        cursor.close()
        return redirect('/doctor/myLeaves')


@app.route('/doctor/profile', methods=['GET', 'POST'])
@login_required
@role_required(['doctor'])
def doctor_profile():
    cursor = conn.cursor()

    if request.method == 'GET':
        cursor.execute("""
            SELECT doctors._id, last_name, first_name, second_name, phone_number, gender, 
                   birthday, addresses.country, addresses.city, addresses.street, addresses.house, 
                   addresses.flat, addresses._id, users.login, university, faculty, specialization, education_id  
            FROM doctors
            JOIN addresses ON addresses._id = doctors.address_id
            JOIN users ON users._id = doctors.user_id 
            JOIN education ON education._id = doctors.education_id
            WHERE users._id = %s
        """, (str(session.get('user_id')),))
        result = cursor.fetchone()
        cursor.close()
        return render_template('doctors/profile.html', user_profile=result)

    elif request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        second_name = request.form.get('second_name')
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')
        gender = request.form.get('gender')

        # Обновление основной информации
        cursor.execute("""
            UPDATE doctors
            SET first_name = %s, last_name = %s, second_name = %s, phone_number = %s, gender = %s
            WHERE user_id = %s
        """, (first_name, last_name, second_name, phone_number, gender, str(session.get('user_id'))))
        conn.commit()

        # Обновление email в таблице users
        cursor.execute("""
            UPDATE users
            SET login = %s
            WHERE _id = %s
        """, (email, str(session.get('user_id'))))
        conn.commit()

        cursor.close()
        return redirect('/doctor/profile')


@app.route('/doctor/profile/address', methods=['POST'])
@login_required
@role_required(['doctor'])
def doctor_profile_address():
    cursor = conn.cursor()

    address_id = request.form.get('address_id')
    country = request.form.get('country')
    city = request.form.get('city')
    street = request.form.get('street')
    house = request.form.get('house')
    flat = request.form.get('flat')

    cursor.execute("""
        UPDATE addresses
        SET country = %s, city = %s, street = %s, house = %s, flat = %s
        WHERE _id = %s
    """, (country, city, street, house, flat, address_id))
    conn.commit()
    cursor.close()
    return redirect('/doctor/profile')


@app.route('/doctor/profile/education', methods=['POST'])
@login_required
@role_required(['doctor'])
def doctor_profile_education():
    cursor = conn.cursor()

    education_id = request.form.get('education_id')
    university = request.form.get('university')
    faculty = request.form.get('faculty')
    specialization = request.form.get('specialization')

    cursor.execute("""
        UPDATE education
        SET university = %s, faculty = %s, specialization = %s
        WHERE _id = %s
    """, (university, faculty, specialization, education_id))
    conn.commit()
    cursor.close()
    return redirect('/doctor/profile')


@app.route('/doctor/profile/password', methods=['POST'])
@login_required
@role_required(['doctor'])
def doctor_change_password():
    cursor = conn.cursor()

    old_password = request.form.get('old-password')
    new_password = request.form.get('new-password')
    repeat_password = request.form.get('repeat-password')

    cursor.execute("SELECT password FROM users WHERE _id = %s", (session.get('user_id'),))

    result = cursor.fetchone()

    decrypted_password = hashlib.sha256((old_password + salt).encode()).hexdigest()

    if result and result[0] == decrypted_password:
        if new_password == repeat_password:
            encrypted_new = hashlib.sha256((new_password + salt).encode()).hexdigest()

            cursor.execute("""
                                        UPDATE users
                                        SET password = %s WHERE _id=%s
                                    """, (str(encrypted_new), session.get('user_id')))
            conn.commit()
            cursor.close()
            return redirect('/doctor/profile')
        else:
            cursor.close()
            return render_template('doctors/profile.html', error_message="Passwords do not match!")
    else:
        cursor.close()
        return render_template('doctors/profile.html', error_message="Old password is incorrect!")


@app.route('/admin/dashboard', methods=['GET'])
@login_required
@role_required(['admin'])
def admin_dashboard():
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM doctors")
    total_doctors = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM patients")
    total_patients = cursor.fetchone()[0]

    today = datetime.now().date()
    cursor.execute("SELECT COUNT(*) FROM talons WHERE date = %s", (today,))
    today_appointments = cursor.fetchone()[0]

    cursor.execute("""
        SELECT EXTRACT(MONTH FROM date) AS month, COUNT(*) AS count
        FROM talons
        GROUP BY month
        ORDER BY month
    """)
    visits_by_month = cursor.fetchall()
    visits_by_month_full = [0] * 12

    for month, count in visits_by_month:
        visits_by_month_full[int(month) - 1] = count

    cursor.execute("""
        SELECT departments.department, COUNT(*) AS count
        FROM talons
        JOIN doctors ON talons.doctor_id = doctors._id
        JOIN departments ON doctors.department_id = departments._id
        GROUP BY departments.department
    """)
    visits_by_department = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) FROM talons")
    all_appointments = cursor.fetchone()[0]
    cursor.close()

    return render_template('adminDashboard.html',
                           total_doctors=total_doctors,
                           total_patients=total_patients,
                           today_appointments=today_appointments,
                           all_appointments=all_appointments,
                           visits_by_month=visits_by_month_full,
                           visits_by_department=visits_by_department)

@app.route('/admin/scheduleList', methods=['GET', 'POST'])
@login_required
@role_required(['admin'])
def admin_scheduleList():
    cursor = conn.cursor()
    current_date = datetime.now().strftime('%Y-%m-%d')
    cursor.execute("SELECT _id, department FROM departments ORDER BY department ASC")
    departments = cursor.fetchall()

    if request.method == 'GET':
        query = """
            SELECT 
                doctors.last_name, doctors.first_name, doctors.second_name, departments.department, 
                shifts.start_time, shifts.end_time, schedules.day_of_week, schedules._id
            FROM schedules
            JOIN doctors ON schedules.doctor_id = doctors._id
            JOIN shifts ON schedules.shift_id = shifts._id
            JOIN departments ON doctors.department_id = departments._id
            ORDER BY doctors.last_name ASC, schedules.day_of_week ASC
        """
        cursor.execute(query)
        result = cursor.fetchall()
        cursor.close()
        return render_template('scheduleList.html', doctors=result, current_date=current_date, departments=departments)

    if request.method == 'POST':
        search_query = request.form.get('search_query', '').strip()
        department_id = request.form.get('department_id', '').strip()
        day_of_week = request.form.get('day_of_week', '').strip()
        query = """
            SELECT 
                doctors.last_name, doctors.first_name, doctors.second_name, departments.department, 
                shifts.start_time, shifts.end_time, schedules.day_of_week, schedules._id
            FROM schedules
            JOIN doctors ON schedules.doctor_id = doctors._id
            JOIN shifts ON schedules.shift_id = shifts._id
            JOIN departments ON doctors.department_id = departments._id
            WHERE TRUE
        """
        params = []

        if search_query:
            query += """
                AND (doctors.first_name ILIKE %s OR doctors.second_name ILIKE %s OR doctors.last_name ILIKE %s)
            """
            params.extend([f"%{search_query}%"] * 3)

        if department_id:
            query += " AND doctors.department_id = %s"
            params.append(department_id)

        if day_of_week:
            query += " AND schedules.day_of_week = %s "
            params.append(day_of_week)

        query += " ORDER BY doctors.last_name ASC, schedules.day_of_week ASC"
        cursor.execute(query, params)
        result = cursor.fetchall()
        cursor.close()
        return render_template('scheduleList.html', doctors=result, current_date=current_date, departments=departments)

@app.route('/admin/delete_schedule', methods=['POST'])
@login_required
@role_required(['admin'])
def delete_schedule():
    selected_values = request.json.get('values')
    print(selected_values)
    cursor = conn.cursor()
    for value in selected_values:
        print(value)
        cursor.execute("DELETE FROM schedules WHERE _id = %s", (value,))
    conn.commit()
    cursor.close()
    return {"status": "success", "message": "Selected schedules deleted"}


@app.route('/admin/delete_appointment', methods=['POST'])
@login_required
@role_required(['admin'])
def delete_appointment():
    selected_values = request.json.get('values')
    print(selected_values)
    cursor = conn.cursor()
    for value in selected_values:
        print(value)
        cursor.execute("DELETE FROM talons WHERE _id = %s", (value,))
    conn.commit()
    cursor.close()
    return {"status": "success", "message": "Selected schedules deleted"}

@app.route('/admin/delete_leave', methods=['POST'])
@login_required
@role_required(['admin'])
def delete_leave():
    selected_values = request.json.get('values')
    print(selected_values)
    cursor = conn.cursor()
    for value in selected_values:
        print(value)
        cursor.execute("DELETE FROM doctorleaves WHERE _id = %s", (value,))
    conn.commit()
    cursor.close()
    return {"status": "success", "message": "Selected schedules deleted"}

@app.route('/admin/delete_doctors', methods=['POST'])
@login_required
@role_required(['admin'])
def delete_doctor():
    selected_values = request.json.get('values')
    print(selected_values)
    cursor = conn.cursor()
    for value in selected_values:
        print(value)
        cursor.execute("""
                   DELETE FROM users
                   WHERE _id = (SELECT user_id FROM doctors WHERE _id = %s)
               """, (value,))
        cursor.execute("DELETE FROM doctors WHERE _id = %s", (value,))
    conn.commit()
    cursor.close()
    return {"status": "success", "message": "Selected schedules deleted"}

@app.route('/admin/delete_patient', methods=['POST'])
@login_required
@role_required(['admin'])
def delete_patient():
    selected_values = request.json.get('values')
    print(selected_values)
    cursor = conn.cursor()
    for value in selected_values:
        print(value)
        cursor.execute("""
                   DELETE FROM users
                   WHERE _id = (SELECT user_id FROM patients WHERE _id = %s)
               """, (value,))
        cursor.execute("DELETE FROM doctors WHERE _id = %s", (value,))
    conn.commit()
    cursor.close()
    return {"status": "success", "message": "Selected schedules deleted"}

# @app.route('/admin/addSchedule', methods=['GET', 'POST'])
# @app.route('/admin/addSchedule/<int:schedule_id>', methods=['GET', 'POST'])
# @login_required
# @role_required(['admin'])
# def add_schedule(schedule_id=None):
#     cursor = conn.cursor()
#     if request.method == 'GET':
#         if schedule_id:
#             cursor.execute("""
#                             SELECT doctors.last_name, doctors.first_name, doctors.second_name, schedule.date,
#                             schedule.start_time, schedule.end_time, schedule._id
#                             FROM doctors JOIN schedule on doctors._id=schedule.doctor_id
#                             WHERE schedule._id = %s
#                         """, (schedule_id,))
#             leave_data = cursor.fetchone()
#             print(leave_data)
#             cursor.close()
#
#             if leave_data:
#                 return render_template('editSchedule.html', leave=leave_data, schedule_id=schedule_id)
#             else:
#                 return "Leave not found", 404
#         else:
#             empty_leave_data = {
#                 'available-days': '',
#                 'from_time': '',
#                 'to_time': '',
#                 'last_name': '',
#                 'first_name': '',
#                 'second_name': ''
#             }
#             return render_template('editSchedule.html', leave=empty_leave_data)
#
#     if request.method == 'POST':
#         doctor_name = request.form.get('doctor_name', '').strip()
#         available_days = request.form.get('available-days', '')
#         from_time = request.form.get('from_date')
#         to_time = request.form.get('to_date')
#
#         if schedule_id:
#             cursor.execute("""
#                         UPDATE schedule
#                         SET date = %s, start_time = %s, end_time = %s
#                         WHERE _id = %s
#                     """, (available_days, from_time, to_time, schedule_id))
#         else:
#             names = doctor_name.split()
#             last_name, first_name, second_name = names
#
#             cursor.execute("""
#                         SELECT doctors._id FROM doctors WHERE doctors.last_name = %s AND doctors.first_name = %s AND doctors.second_name = %s
#                     """, (last_name, first_name, second_name))
#
#             doctor_id = cursor.fetchone()
#             print(doctor_id)
#             cursor.execute("""
#                         INSERT INTO schedule (doctor_id, date, start_time, end_time)
#                         VALUES (%s, %s, %s, %s)
#                     """, (doctor_id, available_days, from_time, to_time))
#
#         conn.commit()
#         cursor.close()
#
#         return redirect('/admin/scheduleList')
@app.route('/admin/addSchedule', methods=['GET', 'POST'])
@app.route('/admin/addSchedule/<int:schedule_id>', methods=['GET', 'POST'])
@login_required
@role_required(['admin'])
def add_schedule(schedule_id=None):
    cursor = conn.cursor()
    if request.method == 'GET':
        if schedule_id:
            cursor.execute("""
                SELECT 
                doctors.last_name, doctors.first_name, doctors.second_name, departments.department, 
                shifts.start_time, shifts.end_time, schedules.day_of_week, schedules._id
                FROM schedules
                JOIN doctors ON schedules.doctor_id = doctors._id
                JOIN shifts ON schedules.shift_id = shifts._id
                JOIN departments ON doctors.department_id = departments._id
                WHERE schedules._id = %s
            """, (schedule_id,))
            schedule_data = cursor.fetchone()
            cursor.execute("SELECT _id, start_time, end_time FROM shifts ORDER BY start_time ASC")
            shifts = cursor.fetchall()
            cursor.close()

            if schedule_data:
                return render_template('editSchedule.html', schedule=schedule_data, shifts=shifts,
                                       schedule_id=schedule_id)
            else:
                return "Schedule not found", 404
        else:
            cursor.execute("SELECT _id, start_time, end_time FROM shifts ORDER BY start_time ASC")
            shifts = cursor.fetchall()
            cursor.close()
            return render_template('editSchedule.html', shifts=shifts, schedule=None)

    if request.method == 'POST':
        doctor_name = request.form.get('doctor_name', '').strip()
        shift_id = request.form.get('shift_id')
        day_of_week = request.form.get('day_of_week')

        if schedule_id:
            cursor.execute("""
                UPDATE schedules
                SET shift_id = %s, day_of_week = %s
                WHERE _id = %s
            """, (shift_id, day_of_week, schedule_id))
        else:
            names = doctor_name.split()
            last_name, first_name, second_name = names

            cursor.execute("""
                SELECT _id FROM doctors 
                WHERE last_name = %s AND first_name = %s AND second_name = %s
            """, (last_name, first_name, second_name))
            doctor_id = cursor.fetchone()

            if doctor_id:
                cursor.execute("""
                    INSERT INTO schedules (doctor_id, shift_id, day_of_week)
                    VALUES (%s, %s, %s)
                """, (doctor_id[0], shift_id, day_of_week))
            else:
                cursor.close()
                return "Doctor not found", 404

        conn.commit()
        cursor.close()

        return redirect('/admin/scheduleList')


@app.route('/admin/doctorLeaves', methods=['GET', 'POST'])
@login_required
@role_required(['admin'])
def admin_doctorLeaves():
    cursor = conn.cursor()
    current_date = datetime.now().strftime('%Y-%m-%d')
    if (request.method == 'GET'):
        cursor.execute(
            "SELECT doctors.last_name, doctors.first_name,  doctors.second_name, doctorLeaves.leave_type, doctorLeaves.from_date, "
            "doctorLeaves.to_date, doctorLeaves.reason, doctorLeaves.status, doctorLeaves._id, "
            "(doctorLeaves.to_date - doctorLeaves.from_date + 1) AS days_count "
            "FROM doctorLeaves JOIN doctors on doctors._id=doctorLeaves.doctor_id "
            "ORDER BY doctors.last_name ASC")
        result = cursor.fetchall()
        cursor.close()
        return render_template('doctorLeaves.html', doctorLeaves=result, current_date=current_date)
    if request.method == 'POST':
        search_query = request.form.get('search_query', '').strip()
        leave_type = request.form.get('leave_type', '').strip()
        status = request.form.get('status', '').strip()
        from_date = request.form.get('from_date', current_date)
        to_date = request.form.get('to_date', current_date)

        query = """
            SELECT doctors.last_name, doctors.first_name, doctors.second_name, doctorLeaves.leave_type, 
                   doctorLeaves.from_date, doctorLeaves.to_date, doctorLeaves.reason, doctorLeaves.status, 
                   doctorLeaves._id, (doctorLeaves.to_date - doctorLeaves.from_date + 1) AS days_count 
            FROM doctorLeaves 
            JOIN doctors on doctors._id = doctorLeaves.doctor_id
            WHERE 1=1
        """
        params = []

        if search_query:
            query += """
                AND (doctors.first_name ILIKE %s OR doctors.second_name ILIKE %s OR doctors.last_name ILIKE %s)
            """
            params.extend([f"%{search_query}%", f"%{search_query}%", f"%{search_query}%"])

        if leave_type:
            query += " AND doctorLeaves.leave_type = %s"
            params.append(leave_type)

        if status:
            query += " AND doctorLeaves.status = %s"
            params.append(status)

        if from_date:
            query += """
                AND doctorLeaves.from_date >= %s
            """
            params.append(from_date)
        if to_date:
            query += """ AND doctorLeaves.to_date <= %s """
            params.append(to_date)

        query += " ORDER BY doctors.last_name ASC"

        print(query, params)

        cursor.execute(query, params)
        result = cursor.fetchall()
        cursor.close()
        return render_template('doctorLeaves.html', doctorLeaves=result, current_date=current_date)


@app.route('/admin/addLeave', methods=['GET', 'POST'])
@app.route('/admin/addLeave/<int:leave_id>', methods=['GET', 'POST'])
@login_required
@role_required(['admin'])
def admin_addLeave(leave_id=None):
    cursor = conn.cursor()
    if request.method == 'GET':
        if leave_id:
            cursor.execute("""
                        SELECT doctorLeaves.leave_type, doctorLeaves.from_date, doctorLeaves.to_date, 
                               doctorLeaves.reason, doctorLeaves.status, doctors.last_name, doctors.first_name, doctors.second_name  
                        FROM doctorLeaves 
                        JOIN doctors ON doctorLeaves.doctor_id = doctors._id 
                        WHERE doctorLeaves._id = %s
                    """, (leave_id,))
            leave_data = cursor.fetchone()
            cursor.close()

            if leave_data:
                return render_template('editLeaves.html', leave=leave_data, leave_id=leave_id)
            else:
                return "Leave not found", 404
        else:
            empty_leave_data = {
                'leave_type': '',
                'from_date': '',
                'to_date': '',
                'reason': '',
                'status': '',
                'first_name': '',
                'last_name': '',
            }
            return render_template('editLeaves.html', leave=empty_leave_data)

    if request.method == 'POST':
        doctor_name = request.form.get('doctor_name', '').strip()
        leave_type = request.form.get('leave_type')
        from_date = request.form.get('from_date')
        to_date = request.form.get('to_date')
        notes = request.form.get('notes')
        status = request.form.get('status')

        if leave_id:
            cursor.execute("""
                    UPDATE doctorLeaves
                    SET leave_type = %s, from_date = %s, to_date = %s, reason = %s, status = %s
                    WHERE _id = %s
                """, (leave_type, from_date, to_date, notes, status, leave_id))
        else:
            names = doctor_name.split()
            last_name, first_name, second_name = names

            cursor.execute("""
                    SELECT doctors._id FROM doctors WHERE doctors.last_name = %s AND doctors.first_name = %s AND doctors.second_name = %s
                """, (last_name, first_name, second_name))

            doctor_id = cursor.fetchone()
            print(doctor_id)
            cursor.execute("""
                    INSERT INTO doctorLeaves (doctor_id, leave_type, from_date, to_date, reason, status)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (doctor_id, leave_type, from_date, to_date, notes, status))

        conn.commit()
        cursor.close()

        return redirect('/admin/doctorLeaves')


@app.route('/admin/appointmentList', methods=['GET', 'POST'])
@login_required
@role_required(['admin'])
def adminAppointmentList():
    cursor = conn.cursor()
    current_date = datetime.now().strftime('%Y-%m-%d')
    if (request.method == 'GET'):
        cursor.execute(
            "SELECT doctors.last_name, doctors.first_name,  doctors.second_name, "
            "patients.last_name, patients.first_name,  patients.second_name, talons.date, talons.time, "
            "talons.status, talons.purpose, talons._id "
            "FROM talons JOIN doctors on doctors._id=talons.doctor_id "
            "JOIN patients on patients._id=talons.patient_id "
            "ORDER BY  talons.time, talons.date DESC")
        result = cursor.fetchall()
        cursor.close()
        return render_template('appointmentList.html', appointments=result, current_date=current_date)
    if (request.method == 'POST'):
        search_query = request.form.get('search_query', '').strip()
        status = request.form.get('status', '').strip()
        from_date = request.form.get('from_date', current_date)
        to_date = request.form.get('to_date', current_date)

        query = """SELECT doctors.last_name, doctors.first_name,  doctors.second_name, 
                patients.last_name, patients.first_name,  patients.second_name, talons.date, talons.time, 
                talons.status, talons.purpose, talons._id 
                FROM talons JOIN doctors on doctors._id=talons.doctor_id 
                JOIN patients on patients._id=talons.patient_id """
        params = []
        if search_query:
            query += """
                    AND (doctors.first_name ILIKE %s OR doctors.second_name ILIKE %s OR doctors.last_name ILIKE %s 
                    OR patients.first_name ILIKE %s OR patients.second_name ILIKE %s OR patients.last_name ILIKE %s)
                """
            params.extend([f"%{search_query}%", f"%{search_query}%", f"%{search_query}%", f"%{search_query}%",
                           f"%{search_query}%", f"%{search_query}%"])
        if status:
            query += " AND talons.status = %s"
            params.append(status)
        query += """
                AND talons.date >= %s
                AND talons.date <= %s
            """
        params.extend([from_date, to_date])
        query += " ORDER BY talons.date, talons.time DESC"
        cursor.execute(query, params)
        result = cursor.fetchall()
        cursor.close()
        return render_template('appointmentList.html', appointments=result, current_date=current_date)


@app.route('/admin/addAppointment', methods=['GET', 'POST'])
@app.route('/admin/addAppointment/<int:appointment_id>', methods=['GET', 'POST'])
@login_required
@role_required(['admin'])
def admin_addAppointment(appointment_id=None):
    cursor = conn.cursor()
    if request.method == 'GET':
        if appointment_id:
            cursor.execute("""
                       SELECT doctors.last_name, doctors.first_name,  doctors.second_name, 
                        patients.last_name, patients.first_name,  patients.second_name, talons.date, talons.time, 
                        talons.status, talons.purpose, talons._id 
                        FROM talons JOIN doctors on doctors._id=talons.doctor_id 
                        JOIN patients on patients._id=talons.patient_id 
                        WHERE talons._id = %s
                    """, (appointment_id,))
            appointment_data = cursor.fetchone()
            cursor.close()

            if appointment_data:
                return render_template('editAppointnment.html', appoinment=appointment_data,
                                       appointment_id=appointment_id)
            else:
                return "Leave not found", 404
        else:
            empty_leave_data = {
                'time': '',
                'date': '',
                'to_date': '',
                'reason': '',
                'status': '',
                'last_name': '',
                'first_name': '',
                'second_name': ''
            }
            return render_template('editAppointnment.html', appoinment=empty_leave_data)

    if request.method == 'POST':
        doctor_name = request.form.get('doctor_name', '').strip()
        patient_name = request.form.get('patient_name', '').strip()
        date = request.form.get('date')
        time = request.form.get('time')
        purpose = request.form.get('reason')
        status = request.form.get('status')

        if appointment_id:
            cursor.execute("""
                    UPDATE talons
                    SET date = %s, time = %s, purpose = %s,status = %s
                    WHERE _id = %s
                """, (date, time, purpose, status, appointment_id))
        else:
            doctor_names = doctor_name.split()
            dlast_name, dfirst_name, dsecond_name = doctor_names
            patient_names = patient_name.split()
            plast_name, pfirst_name, psecond_name = patient_names
            cursor.execute("""
                    SELECT doctors._id FROM doctors WHERE doctors.last_name = %s AND doctors.first_name = %s AND doctors.second_name = %s
                """, (dlast_name, dfirst_name, dsecond_name))

            doctor_id = cursor.fetchone()
            cursor.execute("""
                    SELECT patients._id FROM patients WHERE patients.last_name = %s AND patients.first_name = %s AND patients.second_name = %s
                """, (plast_name, pfirst_name, psecond_name))

            patient_id = cursor.fetchone()
            print(doctor_id)
            cursor.execute("""
                    INSERT INTO talons (doctor_id, patient_id, date, time, purpose, status)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (doctor_id, patient_id, date, time, purpose, status))

        conn.commit()
        cursor.close()

        return redirect('/admin/appointmentList')


@app.route('/admin/patientsList', methods=['GET', 'POST'])
@login_required
@role_required(['admin'])
def admin_patientsList():
    cursor = conn.cursor()
    if (request.method == 'GET'):
        cursor.execute("SELECT patients.last_name, patients.first_name, patients.second_name, patients.phone_number, "
                       "patients.gender, country, city, street, house, flat, patients._id, patients.email "
                       "FROM patients JOIN addresses on addresses._id=patients.address_id "
                       "ORDER BY patients.last_name ASC")
        result = cursor.fetchall()
        cursor.close()
        return render_template('patientsList.html', patients=result)
    if (request.method == 'POST'):
        search_query = request.form.get('search_query', '').strip()
        search_query = f"%{search_query}%"
        cursor.execute("""
                        SELECT patients.last_name, patients.first_name, patients.second_name, patients.phone_number, 
                       patients.gender, country, city, street, house, flat, patients._id, patients.email
                       FROM patients JOIN addresses on addresses._id=patients.address_id 
                       WHERE patients.first_name ILIKE %s OR patients.second_name ILIKE %s OR patients.last_name ILIKE %s 
                       ORDER BY patients.last_name ASC;""", (search_query, search_query, search_query))
        search = cursor.fetchall()
        print(search)
        return render_template('patientsList.html', patients=search)


@app.route('/admin/addPatient', methods=['GET', 'POST'])
@app.route('/admin/addPatient/<int:patient_id>', methods=['GET', 'POST'])
@login_required
@role_required(['admin'])
def admin_addPatient(patient_id=None):
    cursor = conn.cursor()
    if request.method == 'GET':
        if patient_id:
            cursor.execute("""
                      SELECT patients.last_name, patients.first_name, patients.second_name, patients.phone_number, 
                       patients.gender, country, city, street, house, flat, patients._id, users.login, b_day 
                       FROM patients JOIN addresses on addresses._id=patients.address_id 
                       JOIN users on users._id=patients.user_id 
                        WHERE patients._id = %s
                    """, (patient_id,))
            patient_data = cursor.fetchone()
            cursor.close()

            if patient_data:
                return render_template('editPatient.html', patient=patient_data, patient_id=patient_id)
        else:
            empty_leave_data = {
                'phone': '',
                'dob': '',
                'email': '',
                'last_name': '',
                'first_name': '',
                'second_name': ''
            }
            return render_template('editPatient.html', patient=empty_leave_data)

    if request.method == 'POST':
        first_name = request.form.get('firstname', '').strip()
        last_name = request.form.get('lastname', '').strip()
        second_name = request.form.get('secondname', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        dob = request.form.get('dob')
        gender = request.form.get('gender')
        country = request.form.get('country')
        city = request.form.get('city')
        street = request.form.get('street')
        house = request.form.get('house')
        flat = request.form.get('flat')
        if patient_id:
            cursor.execute("""
                    UPDATE patients
                    SET phone_number = %s, b_day = %s, gender = %s, email=%s
                    WHERE _id = %s
                """, (phone, dob, gender, email, patient_id))
            conn.commit()
            cursor.execute("""SELECT patients.address_id FROM patients WHERE patients._id = %s""",
                           (patient_id,))
            address_id = cursor.fetchone()
            cursor.execute("""
                                UPDATE addresses
                                SET country=%s, city = %s, street = %s, house = %s, flat=%s
                                WHERE _id = %s
                            """, (country, city, street, house, flat, address_id))
            conn.commit()
            cursor.execute("""SELECT patients.user_id FROM patients WHERE patients._id = %s""",
                           (patient_id,))
            user_id = cursor.fetchone()
            cursor.execute("""
                                               UPDATE users
                                               SET login=%s
                                               WHERE _id = %s
                                           """, (email, user_id))
            conn.commit()
        else:

            cursor.execute("""INSERT INTO addresses(country, city, house, flat, street)
            VALUES (%s, %s, %s, %s, %s)""", (country, city, house, flat, street))
            conn.commit()

            cursor.execute("""SELECT addresses._id FROM addresses 
            WHERE country=%s AND city=%s AND house=%s AND flat=%s AND street=%s""",
                           (country, city, house, flat, street))
            address_id = cursor.fetchone()

            decrypted_password = hashlib.sha256(("123" + salt).encode()).hexdigest()
            cursor.execute("""INSERT INTO users(login, password, role_id)
                                        VALUES (%s, %s, %s)""", (email, decrypted_password, 1))
            conn.commit()

            cursor.execute("""SELECT users._id FROM users 
                                        WHERE login=%s AND role_id=%s""",
                           (email, 1))
            user_id = cursor.fetchone()

            cursor.execute("""
                    INSERT INTO patients(first_name, last_name, second_name, phone_number, email, b_day, address_id, user_id, gender)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (first_name, last_name, second_name, phone, email, dob, address_id, user_id, gender))
            conn.commit()
            cursor.close()

        return redirect('/admin/patientsList')


@app.route('/admin/doctorsList', methods=['GET', 'POST'])
@login_required
@role_required(['admin'])
def admin_doctorsList():
    cursor = conn.cursor()
    cursor.execute("SELECT _id, department FROM departments ORDER BY department ASC")
    departments = cursor.fetchall()

    if (request.method == 'GET'):
        cursor.execute("SELECT doctors._id, last_name, first_name, second_name, departments.department, phone_number,"
                       "start_date, users.login, university, faculty, specialization "
                       "FROM doctors JOIN addresses on addresses._id=doctors.address_id "
                       "JOIN users on users._id=doctors.user_id "
                       "JOIN departments on departments._id = doctors.department_id "
                       "JOIN education on education._id=doctors.education_id "
                       "ORDER BY doctors.last_name ASC")
        result = cursor.fetchall()
        cursor.close()
        return render_template('doctorsList.html', doctors=result, departments=departments)
    if (request.method == 'POST'):
        search_query = request.form.get('search_query', '').strip()
        department_id = request.form.get('department_id', '').strip()
        search_query = f"%{search_query}%"
        query = """
                SELECT doctors._id, last_name, first_name, second_name, departments.department, phone_number,
                start_date, users.login, university, faculty, specialization 
                FROM doctors JOIN addresses on addresses._id=doctors.address_id 
                JOIN users on users._id=doctors.user_id 
                JOIN departments on departments._id = doctors.department_id 
                JOIN education on education._id=doctors.education_id 
        """
        params = []
        if search_query:
            query += """
                        WHERE (first_name ILIKE %s OR second_name ILIKE %s OR last_name ILIKE %s)
                    """
            params.extend([search_query, search_query, search_query])
        if department_id:
            query += " AND department_id = %s"
            params.append(department_id)

        query += " ORDER BY last_name ASC"
        cursor.execute(query, params)
        search = cursor.fetchall()
        return render_template('doctorsList.html', doctors=search, departments=departments)


@app.route('/admin/addDoctor', methods=['GET', 'POST'])
@app.route('/admin/addDoctor/<int:doctor_id>', methods=['GET', 'POST'])
@login_required
@role_required(['admin'])
def admin_addDoctor(doctor_id=None):
    cursor = conn.cursor()
    cursor.execute("SELECT _id, department FROM departments ORDER BY department ASC")
    departments = cursor.fetchall()
    if request.method == 'GET':
        if doctor_id:
            cursor.execute("""
                      SELECT doctors._id, last_name, first_name, second_name, departments.department, phone_number, 
                        users.login, gender, university, faculty, specialization, birthday, country, city, street, house, flat   
                        FROM doctors JOIN addresses on addresses._id=doctors.address_id 
                        JOIN users on users._id=doctors.user_id 
                        JOIN departments on departments._id = doctors.department_id 
                        JOIN education on education._id=doctors.education_id
                        WHERE doctors._id = %s
                    """, (doctor_id,))
            doctor_data = cursor.fetchone()
            cursor.close()

            if doctor_data:
                return render_template('editDoctor.html', doctor=doctor_data, doctor_id=doctor_id,
                                       departments=departments)
        else:
            empty_leave_data = {
                'phone': '',
                'dob': '',
                'email': '',
                'last_name': '',
                'first_name': '',
                'second_name': ''
            }
            return render_template('editDoctor.html', doctor=empty_leave_data, departments=departments)

    if request.method == 'POST':
        first_name = request.form.get('firstname', '').strip()
        last_name = request.form.get('lastname', '').strip()
        second_name = request.form.get('secondname', '').strip()
        email = request.form.get('email', '').strip()
        phone = request.form.get('phone', '').strip()
        dob = request.form.get('dob')
        gender = request.form.get('gender')
        country = request.form.get('country')
        city = request.form.get('city')
        street = request.form.get('street')
        house = request.form.get('house')
        flat = request.form.get('flat')
        department = request.form.get('department')
        university = request.form.get('university')
        faculty = request.form.get('faculty')
        specialization = request.form.get('specialization')
        if doctor_id:
            cursor.execute("""
                    UPDATE doctors
                    SET phone_number = %s, birthday = %s, gender = %s
                    WHERE _id = %s
                """, (phone, dob, gender, doctor_id))
            conn.commit()
            cursor.execute("""SELECT doctors.address_id FROM doctors WHERE doctors._id = %s""",
                           (doctor_id,))
            address_id = cursor.fetchone()
            cursor.execute("""
                                UPDATE addresses
                                SET country=%s, city = %s, street = %s, house = %s, flat=%s
                                WHERE _id = %s
                            """, (country, city, street, house, flat, address_id))
            conn.commit()
            cursor.execute("""SELECT doctors.education_id FROM doctors WHERE doctors._id = %s""",
                           (doctor_id,))
            education_id = cursor.fetchone()
            cursor.execute("""
                                   UPDATE education
                                   SET university=%s, faculty = %s, specialization = %s
                                   WHERE _id = %s
                               """, (university, faculty, specialization, education_id))
            conn.commit()
            cursor.execute("""SELECT doctors.user_id FROM doctors WHERE doctors._id = %s""",
                           (doctor_id,))
            user_id = cursor.fetchone()
            cursor.execute("""
                                   UPDATE users
                                   SET login=%s
                                   WHERE _id = %s
                               """, (email, user_id))
            conn.commit()

            cursor.execute("""
                                   UPDATE doctors
                                   SET department_id=%s
                                   WHERE _id = %s
                               """, (department, doctor_id))
            conn.commit()

        else:

            cursor.execute("""SELECT addresses._id FROM addresses 
                        WHERE country=%s AND city=%s AND house=%s AND flat=%s AND street=%s""",
                           (country, city, house, flat, street))
            address_id = cursor.fetchone()
            if address_id is None:
                cursor.execute("""INSERT INTO addresses(country, city, house, flat, street)
                VALUES (%s, %s, %s, %s, %s)""", (country, city, house, flat, street))
                conn.commit()
                cursor.execute("""SELECT addresses._id FROM addresses 
                WHERE country=%s AND city=%s AND house=%s AND flat=%s AND street=%s""",
                               (country, city, house, flat, street))
                address_id = cursor.fetchone()

            cursor.execute("""SELECT education._id FROM education 
             WHERE university=%s AND faculty=%s AND specialization=%s""", (university, faculty, specialization))
            education_id = cursor.fetchone()
            if education_id == None:
                cursor.execute("""INSERT INTO education(university, faculty, specialization)
                VALUES (%s, %s, %s)""", (university, faculty, specialization))
                conn.commit()

                cursor.execute("""SELECT education._id FROM education 
                WHERE university=%s AND faculty=%s AND specialization=%s""", (university, faculty, specialization))
                education_id = cursor.fetchone()

            decrypted_password = hashlib.sha256(("123" + salt).encode()).hexdigest()
            cursor.execute("""INSERT INTO users(login, password, role_id)
                            VALUES (%s, %s, %s)""", (email, decrypted_password, 2))
            conn.commit()

            cursor.execute("""SELECT users._id FROM users 
                            WHERE login=%s AND role_id=%s""",
                           (email, 2))
            user_id = cursor.fetchone()
            print(first_name, last_name, second_name, phone, education_id, address_id, user_id, gender, department, dob)
            cursor.execute("""
                    INSERT INTO doctors(first_name, last_name, second_name, phone_number, education_id, address_id, 
                    user_id, gender, department_id, birthday)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                first_name, last_name, second_name, phone, education_id, address_id, user_id, gender, department, dob))
            conn.commit()
            cursor.close()

        return redirect('/admin/doctorsList')


if __name__ == '__main__':
    app.run(debug=True)
