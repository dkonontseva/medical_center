import hashlib
from datetime import datetime, timedelta
from functools import wraps

import jwt
import psycopg2
from flask import Flask, request, render_template, redirect, jsonify
from flask_jwt_extended import JWTManager, jwt_required

app = Flask(__name__)
app.secret_key = '8sJqMOWkUCy2tW6Xiubx'
salt = 'VsikgpaJavBH_v8OvEl'
exp_time=15

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
def contains_forbidden_chars(string):
    forbidden_chars = [' ', '$', '#', '<', '>', '&', '^', '*', '-', '!', '@', '№', '%', ':', ';', '?', '/', '+', '=',
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
            return render_template('auth.html', error_message="You need to log in to get access.")  # Перенаправляем на страницу логина при отсутствии токена

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


@app.route('/', methods=['GET','POST'])
def index():
    return redirect('/login')
    # return redirect('/patientDashboard')

@app.route('/registration', methods=['GET','POST'])
def registration():
    if request.method=='POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']
        repeat_password = request.form['repeat_password']

        if not name or not password:
            return render_template('registration.html', error_message="Please!!! Fill the gaps.")

        if len(password) < 8:
            return render_template('registration.html', error_message="Password should be at least 8 characters long.")

        if password != repeat_password:
            return render_template('registration.html', error_message="Passwords do not match.")

        if contains_forbidden_chars(name) or password_forbidden_chars(password):
            return render_template('registration.html',
                                   error_message="Username and password shouldn't contain specific symbols.")

        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE login = %s", (email,))
        result = cursor.fetchone()
        cursor.close()

        if result[0] > 0:
            return render_template('registration.html',
                                   error_message="User with this name already exists.")

        hashed_password = hashlib.sha256((password + salt).encode()).hexdigest()

        cursor = conn.cursor()
        cursor.execute("INSERT INTO users(login, password, role_id) VALUES(%s, %s, %s)", (email, hashed_password, 2),)
        conn.commit()
        cursor.close()
        return render_template('auth.html')
    else:
        return render_template('registration.html')


@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
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
            response = redirect('/patientDashboard')
            response.set_cookie('token', token)
            return response
        else:
            return render_template('auth.html', error_message="Incorrect password. Please try again.")
    else:
        return render_template('auth.html')


@app.route('/patientDashboard', methods=['GET','POST'])
def patient_dashboard():
    return render_template('patients/dashboard.html')

@app.route('/patientProfile', methods=['GET','POST'])
def patient_profile():
    cursor = conn.cursor()

    if request.method=='GET':
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
            """, (str(first_name), str(last_name), str(second_name), str(email), str(phone_number), str(gender), date_of_birth, str(user.get_id())))
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
    if request.method=='POST':
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


@app.route('/myMedicalCard', methods=['GET','POST'])
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

    if(request.method == 'GET'):
        cursor = conn.cursor()
        cursor.execute("""SELECT doctors.first_name, doctors.second_name, medical_card.date, medical_card._id FROM medical_card 
                                join patients on medical_card.patient_id=patients._id 
                                join doctors on medical_card.doctor_id = doctors._id
                                where user_id=%s""", (str(user.get_id())))
        result=cursor.fetchall()
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
    record=cursor.fetchone()
    conn.close()

    return render_template('patients/medicaCardNote.html', record=record)

@app.route('/searchMedNote', methods=['GET','POST'])
def searchMedNote():
    search_query=request.form.get('search_query')
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
    doctor_id = user.get_id()
    today = datetime.now().date()

    cursor = conn.cursor()
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
        FROM appointments a
        JOIN patients p ON a.patient_id = p._id
        WHERE a.doctor_id = %s AND a.date > %s
        ORDER BY a.date, a.time
    """, (doctor_id, today))
    upcoming_appointments = cursor.fetchall()

    cursor.execute("""
        SELECT a._id, p.first_name, p.last_name, a.time, a.purpose, a.status
        FROM appointments a
        JOIN patients p ON a.patient_id = p._id
        WHERE a.doctor_id = %s AND a.date = %s
        ORDER BY a.time
    """, (doctor_id, today))
    today_appointments = cursor.fetchall()

    cursor.close()
    return render_template('doctors/dashboard.html',
                           upcoming_appointments=upcoming_appointments,
                           today_appointments=today_appointments)

@app.route('/doctor/add_note/<int:appointment_id>', methods=['GET', 'POST'])
def add_note(appointment_id):
    cursor = conn.cursor()

    if request.method == 'POST':
        doctor_id = user.get_id()
        date=request.form.get('date')
        symptoms = request.form.get('symptoms')
        results = request.form.get('results')
        diagnosis = request.form.get('diagnosis')
        action = request.form.get('action')
        if action == 'add':
            cursor.execute("SELECT patient_id from talons where _id=%s", str(appointment_id))
            patient_id = cursor.fetchone()
            cursor.execute("INSERT INTO medical_card(patient_id, doctor_id, date, complaints, wellness_check, disease) "
                           "VALUES (%s, %s, %s, %s, %s, %s)", str(patient_id[0]),str(doctor_id), datetime(date),
                           symptoms,results,diagnosis)
            conn.commit()
            cursor.close()

            return redirect('/doctor/dashboard')

        elif action == 'cancel':
            cursor.execute("""
                           UPDATE talons
                           SET status = 'cancelled'
                           WHERE _id = %s AND doctor_id = %s
                       """, (appointment_id, doctor_id))
            conn.commit()
            cursor.close()
            return redirect('/doctor/dashboard')
@app.route('/addpatient', methods=['GET','POST'])
# @token_required
def addpatient():
    if request.method=='POST':
        name = request.form['fio']
        surname = request.form['surname']
        secondname=request.form['secondname']
        email = request.form['email']
        phone = request.form['phone']
        address=request.form['address']
        dob=request.form['dob']
        gender=request.form['gender']
        medicalCard=request.form['medicalCard']
        lastVisit=request.form['lastVisit']
        medicalHistory=request.form['medicalHistory']

        cursor = conn.cursor()
        query= "INSERT INTO patients(first_name, last_name, second_name, phone_number, email, b_day) VALUES(%s,%s, %s, %s, %s, %s)"
        cursor.execute(query, (name, surname, secondname, phone, email, dob), )
        print(query)
        conn.commit()
        cursor.close()
        return render_template('patients/dashboard.html')
    else:
        return render_template('addPatient.html')


if __name__ == '__main__':
    app.run(debug=True)
