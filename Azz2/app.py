from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Функция для подключения к базе данных
def get_db_connection():
    conn = sqlite3.connect('courier_management.db')  # Название совпадает с add_admin.py
    conn.row_factory = sqlite3.Row
    return conn

# Главная страница
@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':  # Если запрос POST, выполняется авторизация
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['username'] = user['username']
            session['role'] = user['role']
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user['role'] == 'courier':
                return redirect(url_for('courier_dashboard'))
        return render_template('login.html', error='Неверный логин или пароль')

    # Если запрос GET, отображается форма авторизации
    return render_template('login.html')

# Регистрация
@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register_post():
    username = request.form['username']
    password = request.form['password']
    role = request.form['role']

    conn = get_db_connection()
    conn.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', (username, password, role))
    conn.commit()
    conn.close()

    return redirect(url_for('home'))

# Админ: Заявки
@app.route('/admin_dashboard')
def admin_dashboard():
    conn = get_db_connection()
    applications = conn.execute('SELECT * FROM applications').fetchall()
    conn.close()
    return render_template('admin_application.html', applications=applications)  # Замените имя шаблона

@app.route('/admin_dashboard', methods=['POST'])
def admin_dashboard_post():
    application_id = request.form['application_id']
    action = request.form['action']
    reason = request.form.get('reason', '')

    conn = get_db_connection()
    if action == 'accept':
        conn.execute('UPDATE applications SET status = "Принята" WHERE id = ?', (application_id,))
    elif action == 'reject':
        conn.execute('UPDATE applications SET status = "Отклонена", reason = ? WHERE id = ?', (reason, application_id))
    conn.commit()
    conn.close()

    return redirect(url_for('admin_dashboard'))

# Админ: История заявок
@app.route('/admin_application_history')
def admin_application_history():
    conn = get_db_connection()
    history = conn.execute('SELECT * FROM applications WHERE status IN ("Принята", "Отклонена")').fetchall()
    conn.close()
    return render_template('admin_history.html', history=history)

# Админ: Курьеры
@app.route('/admin_couriers')
def admin_couriers():
    conn = get_db_connection()
    couriers = conn.execute('SELECT * FROM couriers').fetchall()
    conn.close()
    return render_template('admin_couriers.html', couriers=couriers)

# Курьер: Панель
@app.route('/courier_dashboard')
def courier_dashboard():
    if 'username' not in session or session.get('role') != 'courier':
        return redirect(url_for('home'))
    return render_template('courier_dashboard.html')

@app.route('/admin_statistics')
def admin_statistics():
    if 'role' in session and session['role'] == 'admin':
        conn = get_db_connection()

        # Общая статистика
        total_applications = conn.execute('SELECT COUNT(*) FROM applications').fetchone()[0]
        accepted_applications = conn.execute('SELECT COUNT(*) FROM applications WHERE status = "accepted"').fetchone()[0]
        rejected_applications = conn.execute('SELECT COUNT(*) FROM applications WHERE status = "rejected"').fetchone()[0]
        pending_applications = conn.execute('SELECT COUNT(*) FROM applications WHERE status = "pending"').fetchone()[0]

        # Курьеры
        total_couriers = conn.execute('SELECT COUNT(*) FROM users WHERE role = "courier"').fetchone()[0]

        conn.close()

        return render_template(
            'admin_statistics.html',
            total_applications=total_applications,
            accepted_applications=accepted_applications,
            rejected_applications=rejected_applications,
            pending_applications=pending_applications,
            total_couriers=total_couriers
        )
    return redirect(url_for('home'))


# Выход
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
