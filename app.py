import hashlib
from datetime import datetime, timedelta
from functools import wraps
from idlelib import query

import jwt
import psycopg2
from flask import Flask, request, render_template, redirect, jsonify

app = Flask(__name__)
app.secret_key = '8sJqMOWkUCy2tW6Xiubx'
salt = 'VsikgpaJavBH_v8OvEl'
exp_time = 15

JWT_SECRET = app.secret_key
JWT_ALGORITHM = 'HS256'
JWT_EXP_DELTA_SECONDS = 360

conn = psycopg2.connect(database="medical_center", user="postgres", password="postgres", host="localhost", port="5433")


class User:
    def __init__(self, user_id):
        self.user_id = user_id

    def get_id(self):
        return self.user_id

    def set_id(self, user_id):
        self.user_id = user_id


user = User(0)


# diana.konontseva@mail.ru diana123
# doctor: diankabelarus@gmail.com vlad1234
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


@app.route('/', methods=['GET', 'POST'])
def index():
    return redirect('/login')
    # return redirect('/patientDashboard')


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
        cursor.execute("INSERT INTO users(login, password, role_id) VALUES(%s, %s, %s)", (email, hashed_password, 2), )
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

        # Retrieve the stored hashed password and salt from the database
        cursor = conn.cursor()
        cursor.execute("SELECT _id, password FROM users WHERE login = %s", (email,))
        result = cursor.fetchone()
        cursor.close()

        if result is None:
            return render_template('auth.html', error_message="Incorrect login. Please try again.")

        stored_password = result[1]
        decrypted_password = hashlib.sha256((password + salt).encode()).hexdigest()

        if decrypted_password == stored_password:
            payload = {
                'email': email,
                'exp': datetime.utcnow() + timedelta(seconds=JWT_EXP_DELTA_SECONDS)
            }
            token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
            user.set_id(result[0])
            # response = redirect('/patientDashboard')
            response = redirect('/doctor/dashboard')
            response.set_cookie('token', token)
            return response
        else:
            return render_template('auth.html', error_message="Incorrect password. Please try again.")
    else:
        return render_template('auth.html')


@app.route('/patientDashboard', methods=['GET', 'POST'])
def patient_dashboard():
    return render_template('patients/dashboard.html')


@app.route('/patientProfile', methods=['GET', 'POST'])
def patient_profile():
    cursor = conn.cursor()

    if request.method == 'GET':
        cursor.execute("SELECT first_name, last_name, second_name, phone_number, email, b_day, gender, country, "
                       "city, street, house, flat, addresses._id  from patients join addresses on patients.address_id = addresses._id "
                       "where user_id=%s", (str(user.get_id())))
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
        str(first_name), str(last_name), str(second_name), str(email), str(phone_number), str(gender), date_of_birth,
        str(user.get_id())))
        conn.commit()

        cursor.close()
        return redirect('/patientProfile')


@app.route('/patientProfileAddress', methods=['POST'])
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
def patient_change_password():
    if request.method == 'POST':
        old_password = request.form.get('old-password')
        new_password = request.form.get('new-password')
        repeat_password = request.form.get('repeat-password')

        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE _id = %s", str(user.get_id()))
        result = cursor.fetchone()

        stored_password = result[0]
        decrypted_password = hashlib.sha256((old_password + salt).encode()).hexdigest()

        if decrypted_password != stored_password:
            return redirect('patientProfile')

        if new_password != repeat_password:
            return redirect('patientProfile')

        encrypted_new = hashlib.sha256((new_password + salt).encode()).hexdigest()

        cursor.execute("""
                        UPDATE users
                        SET password = %s WHERE _id=%s
                    """, (str(encrypted_new), str(user.get_id())))
        conn.commit()
        cursor.close()

    return redirect('/patientProfile')


@app.route('/myMedicalCard', methods=['GET', 'POST'])
def myMedicalCard():
    if request.method == 'POST':
        search_query = request.form.get('search_query', '').strip()
        search_query = f"%{search_query}%"
        cursor = conn.cursor()
        cursor.execute("""
                SELECT doctors.first_name, doctors.second_name, medical_card.date, medical_card._id
                FROM medical_card
                JOIN patients ON medical_card.patient_id = patients._id
                JOIN doctors ON medical_card.doctor_id = doctors._id
                WHERE patients.user_id = %s AND (doctors.first_name ILIKE %s OR doctors.second_name ILIKE %s);
            """, (user.get_id(), search_query, search_query))
        search = cursor.fetchall()
        print(search)
        return render_template('patients/medicalCard.html', medicalCard=search)

    if (request.method == 'GET'):
        cursor = conn.cursor()
        cursor.execute("""SELECT doctors.first_name, doctors.second_name, medical_card.date, medical_card._id FROM medical_card 
                                join patients on medical_card.patient_id=patients._id 
                                join doctors on medical_card.doctor_id = doctors._id
                                where user_id=%s""", (str(user.get_id())))
        result = cursor.fetchall()
        cursor.close()
        return render_template('patients/medicalCard.html', medicalCard=result)


@app.route('/medicalRecord/<int:record_id>', methods=['GET'])
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
def searchMedNote():
    search_query = request.form.get('search_query')
    if (request.method == 'POST'):
        cursor = conn.cursor()
        print(cursor.execute("""SELECT doctors.first_name, doctors.second_name, medical_card.date, medical_card._id
                                FROM medical_card
                                JOIN patients ON medical_card.patient_id = patients._id
                                JOIN doctors ON medical_card.doctor_id = doctors._id
                                WHERE patients.user_id = %s AND (doctors.first_name ILIKE %s OR doctors.second_name ILIKE %s);
                                """,
                             (str(user.get_id()), search_query, search_query)))
        search = cursor.fetchall()
        cursor.close()
    return render_template('patients/medicalCard.html', medicalCard=search)


@app.route('/findAppointment', methods=['GET'])
def findAppointment():
    cursor = conn.cursor()

    doctor_id = request.args.get('doctor_id')

    if doctor_id:  # Если запрос на получение свободных слотов
        cursor.execute("""
            SELECT s.date, s.start_time, s.end_time
            FROM schedule s
            WHERE s.doctor_id = %s AND s.date >= CURRENT_DATE
            ORDER BY s.date, s.start_time
        """, (doctor_id,))
        schedule = cursor.fetchall()

        free_slots = []
        for row in schedule:
            date, start_time, end_time = row
            start_datetime = datetime.combine(date, start_time)
            end_datetime = datetime.combine(date, end_time)

            all_slots = []
            while start_datetime < end_datetime:
                all_slots.append(start_datetime.time())
                start_datetime += timedelta(minutes=30)

            # Получение занятых слотов
            cursor.execute("""
                SELECT time
                FROM talons
                WHERE doctor_id = %s AND date = %s
            """, (doctor_id, date))
            occupied_slots = {slot[0] for slot in cursor.fetchall()}

            free_slots.extend([
                {"date": date.strftime("%Y-%m-%d"), "time": slot.strftime("%H:%M")}
                for slot in all_slots if slot not in occupied_slots
            ])

        cursor.close()
        return jsonify({"available_slots": free_slots})

    else:  # Запрос списка врачей
        cursor.execute("""
            SELECT DISTINCT d._id, d.first_name, d.last_name, d.second_name, d.phone_number
            FROM doctors d
            ORDER BY d.last_name, d.first_name
        """)
        doctors = cursor.fetchall()
        cursor.close()

        doctors_list = [
            {"id": doc[0], "first_name": doc[1], "last_name": doc[2], "second_name": doc[3], "phone_number": doc[4]}
            for doc in doctors
        ]
        return render_template('patients/findAppointment.html', doctors=doctors_list)


@app.route('/bookAppointment', methods=['POST'])
def bookAppointment():
    doctor_id = request.form.get('doctor_id')
    slot_date = request.form.get('date')
    slot_time = request.form.get('time')
    patient_id = user.get_id()

    if not doctor_id or not slot_date or not slot_time:
        return jsonify({"error": "Doctor ID, date, and time are required"}), 400

    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO talons (patient_id, doctor_id, date, time)
        VALUES (%s, %s, %s, %s)
    """, (patient_id, doctor_id, slot_date, slot_time))
    conn.commit()
    cursor.close()

    return jsonify({"message": "Appointment booked successfully!"})


@app.route('/doctor/dashboard', methods=['GET', 'POST'])
def doctor_dashboard():
    cursor = conn.cursor()
    cursor.execute(""" SELECT _id FROM doctors WHERE user_id = %s""", str(user.get_id()))
    doctor_id = cursor.fetchone()
    print(doctor_id)
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
                SET status = 'cancelled'
                WHERE _id = %s AND doctor_id = %s
            """, (appointment_id, doctor_id))
        conn.commit()

    cursor.execute("""
        SELECT a._id, p.first_name, p.last_name, a.date, a.time, a.purpose, a.status
        FROM talons a
        JOIN patients p ON a.patient_id = p._id
        WHERE a.doctor_id = %s AND a.date > %s AND a.status != 'cancelled'
        ORDER BY a.date, a.time
    """, (doctor_id, today))
    upcoming_appointments = cursor.fetchall()

    cursor.execute("""
        SELECT a._id, p.first_name, p.last_name, a.time, a.purpose, a.status,  a.patient_id
        FROM talons a
        JOIN patients p ON a.patient_id = p._id
        WHERE a.doctor_id = %s AND a.date = %s AND a.status != 'cancelled'
        ORDER BY a.time
    """, (doctor_id, today))
    today_appointments = cursor.fetchall()
    print(today_appointments)

    cursor.close()
    return render_template('doctors/dashboard.html',
                           upcoming_appointments=upcoming_appointments,
                           today_appointments=today_appointments)


@app.route('/doctor/add_note/<int:patient_id>', methods=['GET', 'POST'])
def add_note(patient_id):
    cursor = conn.cursor()
    # Получение данных врача
    cursor.execute(""" SELECT _id, first_name, last_name FROM doctors WHERE user_id = %s""", (str(user.get_id()),))
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
            """, (user.get_id(), search_query, search_query))
        search = cursor.fetchall()
        print(search)
        return render_template('doctors/patientsCards.html', medicalCard=search)

    if (request.method == 'GET'):
        cursor.execute("""SELECT patients.last_name, patients.first_name, medical_card.date, medical_card._id FROM medical_card 
                                join patients on medical_card.patient_id=patients._id 
                                join doctors on medical_card.doctor_id = doctors._id
                                where doctors.user_id=%s ORDER BY medical_card.date DESC """, (str(user.get_id())))
        result = cursor.fetchall()
        cursor.close()
        return render_template('doctors/patientsCards.html', medicalCard=result)


@app.route('/doctor/medicalRecord/<int:record_id>', methods=['GET'])
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


@app.route('/doctor/profile', methods=['GET', 'POST'])
def doctor_profile():
    cursor = conn.cursor()

    if request.method == 'GET':
        cursor.execute("SELECT last_name, first_name, second_name, phone_number, login, gender, country, "
                       "city, street, house, flat, addresses._id  from doctors join addresses on doctors.address_id = addresses._id "
                       "join users on doctors.user_id=users._id "
                       "where user_id=%s", (str(user.get_id())))
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

        cursor.execute("""
                UPDATE doctors
                SET first_name = %s, last_name = %s, second_name = %s, phone_number = %s, gender = %s
                WHERE user_id = %s
            """, (str(first_name), str(last_name), str(second_name), str(email), str(phone_number), str(gender),
                  str(user.get_id())))
        conn.commit()

        cursor.execute("""
                           UPDATE users
                           SET login = %s
                           WHERE user_id = %s""", (str(user.get_id())))
        conn.commit()

        cursor.close()
        return redirect('/doctor/profile')


@app.route('/addpatient', methods=['GET', 'POST'])
# @token_required
def addpatient():
    if request.method == 'POST':
        name = request.form['fio']
        surname = request.form['surname']
        secondname = request.form['secondname']
        email = request.form['email']
        phone = request.form['phone']
        address = request.form['address']
        dob = request.form['dob']
        gender = request.form['gender']

        cursor = conn.cursor()
        query = "INSERT INTO patients(first_name, last_name, second_name, phone_number, email, b_day) VALUES(%s,%s, %s, %s, %s, %s)"
        cursor.execute(query, (name, surname, secondname, phone, email, dob), )
        print(query)
        conn.commit()
        cursor.close()
        return render_template('patients/dashboard.html')
    else:
        return render_template('addPatient.html')


@app.route('/admin/adminDashboard', methods=['GET', 'POST'])
def admin_dashboard():
    return render_template('adminDashboard.html')


@app.route('/admin/patientsList', methods=['GET', 'POST'])
def admin_patientsList():
    cursor = conn.cursor()
    if (request.method == 'GET'):
        cursor.execute("SELECT patients.last_name, patients.first_name, patients.second_name, patients.phone_number, "
                       "patients.gender, country, city, street, house, flat, patients._id, users.login  "
                       "FROM patients JOIN addresses on addresses._id=patients.address_id "
                       "JOIN users on users._id=patients.user_id "
                       "ORDER BY patients.last_name ASC")
        result = cursor.fetchall()
        cursor.close()
        return render_template('patientsList.html', patients=result)
    if (request.method == 'POST'):
        search_query = request.form.get('search_query', '').strip()
        search_query = f"%{search_query}%"
        cursor.execute("""
                        SELECT patients.last_name, patients.first_name, patients.second_name, patients.phone_number, 
                       patients.gender, country, city, street, house, flat, patients._id, users.login  
                       FROM patients JOIN addresses on addresses._id=patients.address_id 
                       JOIN users on users._id=patients.user_id 
                       WHERE patients.first_name ILIKE %s OR patients.second_name ILIKE %s OR patients.last_name ILIKE %s 
                       ORDER BY patients.last_name ASC;""", (search_query, search_query, search_query))
        search = cursor.fetchall()
        print(search)
        return render_template('patientsList.html', patients=search)


@app.route('/admin/doctorsList', methods=['GET', 'POST'])
def admin_doctorsList():
    cursor = conn.cursor()
    if (request.method == 'GET'):
        cursor.execute("SELECT patients.first_name, patients.last_name, patients.second_name, patients.phone_number, "
                       "patients.gender,medical_card._id, country, city, street, house, flat "
                       "FROM patients JOIN addresses on addresses._id=atients.address_id "
                       "JOIN medical_card on medical_card.patient_id = patients._id "
                       "ORDER BY patients.last_name ASC")
        result = cursor.fetchall()
        cursor.close()
        return render_template('doctorsList.html', patients=result)
    if (request.method == 'POST'):
        search_query = request.form.get('search_query', '').strip()
        search_query = f"%{search_query}%"
        cursor.execute("""
                            SELECT doctors.first_name, doctors.last_name, doctors.second_name,  
                           FROM patients JOIN addresses on addresses._id=patients.address_id 
                           JOIN medical_card on medical_card.patient_id = patients._id 
                           WHERE patients.first_name ILIKE %s OR patients.second_name ILIKE %s OR patients.last_name ILIKE %s 
                           ORDER BY patients.last_name ASC;""", (search_query, search_query, search_query))
        search = cursor.fetchall()
        print(search)
        return render_template('doctorsList.html', medicalCard=search)

@app.route('/admin/scheduleList', methods=['GET', 'POST'])
def admin_scheduleList():
    cursor = conn.cursor()
    current_date = datetime.now().strftime('%Y-%m-%d')
    if (request.method == 'GET'):
        cursor.execute("SELECT doctors.last_name, doctors.first_name, doctors.second_name, schedule.date, "
                       "schedule.start_time, schedule.end_time, schedule._id FROM doctors JOIN schedule on doctors._id=schedule.doctor_id "
                       "ORDER BY doctors.last_name ASC")
        result = cursor.fetchall()
        cursor.close()
        return render_template('scheduleList.html', doctors=result, current_date=current_date)
    if request.method == 'POST':
        search_query = request.form.get('search_query', '').strip()
        from_date = request.form.get('from_date', current_date)
        to_date = request.form.get('to_date', current_date)
        query="""
            SELECT doctors.last_name, doctors.first_name, doctors.second_name, schedule.date, 
                   schedule.start_time, schedule.end_time, schedule._id  
            FROM doctors JOIN schedule ON doctors._id = schedule.doctor_id """
        params = []
        if search_query:
            query += """
                        AND (doctors.first_name ILIKE %s OR doctors.second_name ILIKE %s OR doctors.last_name ILIKE %s)
                    """
            params.extend([f"%{search_query}%", f"%{search_query}%", f"%{search_query}%"])
        query += """
                    AND  schedule.date>= %s
                    AND schedule.date <= %s
                """
        params.extend([from_date, to_date])
        query += " ORDER BY doctors.last_name ASC"
        cursor.execute(query, params)
        result = cursor.fetchall()
        cursor.close()
        return render_template('scheduleList.html', doctors=result, current_date=current_date)
@app.route('/admin/addSchedule', methods=['GET', 'POST'])
@app.route('/admin/addSchedule/<int:schedule_id>', methods=['GET', 'POST'])
def add_schedule(schedule_id=None):
    cursor = conn.cursor()
    if request.method == 'GET':
        if schedule_id:
            cursor.execute("""
                            SELECT doctors.last_name, doctors.first_name, doctors.second_name, schedule.date, 
                            schedule.start_time, schedule.end_time, schedule._id 
                            FROM doctors JOIN schedule on doctors._id=schedule.doctor_id 
                            WHERE schedule._id = %s
                        """, (schedule_id,))
            leave_data = cursor.fetchone()
            print(leave_data)
            cursor.close()

            if leave_data:
                return render_template('editSchedule.html', leave=leave_data, schedule_id=schedule_id)
            else:
                return "Leave not found", 404
        else:
            empty_leave_data = {
                'available-days': '',
                'from_time': '',
                'to_time': '',
                'last_name': '',
                'first_name': '',
                'second_name': ''
            }
            return render_template('editSchedule.html', leave=empty_leave_data)

    if request.method == 'POST':
        doctor_name = request.form.get('doctor_name', '').strip()
        available_days = request.form.get('available-days', '')
        from_time = request.form.get('from_date')
        to_time = request.form.get('to_date')

        if schedule_id:
            cursor.execute("""
                        UPDATE schedule
                        SET date = %s, start_time = %s, end_time = %s
                        WHERE _id = %s
                    """, (available_days, from_time, to_time, schedule_id))
        else:
            names = doctor_name.split()
            last_name, first_name, second_name = names

            cursor.execute("""
                        SELECT doctors._id FROM doctors WHERE doctors.last_name = %s AND doctors.first_name = %s AND doctors.second_name = %s
                    """, (last_name, first_name, second_name))

            doctor_id = cursor.fetchone()
            print(doctor_id)
            cursor.execute("""
                        INSERT INTO schedule (doctor_id, date, start_time, end_time)
                        VALUES (%s, %s, %s, %s)
                    """, (doctor_id, available_days, from_time, to_time))

        conn.commit()
        cursor.close()

        return redirect('/admin/scheduleList')

@app.route('/admin/doctorLeaves', methods=['GET', 'POST'])
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
    if (request.method == 'POST'):
        search_query = request.form.get('search_query', '').strip()
        leave_type = request.form.get('leave_type', '').strip()
        status = request.form.get('status', '').strip()
        from_date = request.form.get('from_date', current_date)
        to_date = request.form.get('to_date', current_date)

        query="""SELECT doctors.last_name, doctors.first_name, doctors.second_name, doctorLeaves.leave_type, doctorLeaves.from_date, 
                       doctorLeaves.to_date, doctorLeaves.reason, doctorLeaves.status, doctorLeaves._id,
                        (doctorLeaves.to_date - doctorLeaves.from_date + 1) AS days_count 
                       FROM doctorLeaves JOIN doctors on doctors._id=doctorLeaves.doctor_id """
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
        query += """
            AND doctorLeaves.from_date >= %s
            AND doctorLeaves.to_date <= %s
        """
        params.extend([from_date, to_date])
        query += " ORDER BY doctors.last_name ASC"
        cursor.execute(query, params)
        result = cursor.fetchall()
        cursor.close()
        return render_template('doctorLeaves.html', doctorLeaves=result, current_date=current_date)
@app.route('/admin/addLeave', methods=['GET', 'POST'])
@app.route('/admin/addLeave/<int:leave_id>', methods=['GET', 'POST'])
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

            doctor_id=cursor.fetchone()
            print(doctor_id)
            cursor.execute("""
                    INSERT INTO doctorLeaves (doctor_id, leave_type, from_date, to_date, reason, status)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (doctor_id, leave_type, from_date, to_date, notes, status))

        conn.commit()
        cursor.close()

        return redirect('/admin/doctorLeaves')

@app.route('/admin/appointmentList', methods=['GET', 'POST'])
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
            params.extend([f"%{search_query}%", f"%{search_query}%", f"%{search_query}%", f"%{search_query}%", f"%{search_query}%", f"%{search_query}%"])
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

if __name__ == '__main__':
    app.run(debug=True)
