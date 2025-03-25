from flask import Flask, render_template, request, redirect, url_for, session
from flask_bcrypt import Bcrypt
import sqlite3
import pandas as pd
import joblib

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
bcrypt = Bcrypt(app)

# Load the trained model
model = joblib.load('trained_ensemble_model.pkl')

# Define the attack type mapping
attack_type_mapping = {
    0: 'Perl_Attack', 1: 'Pod_Attack', 2: 'Mscan_Attack', 3: 'Xsnoop_Attack',
    4: 'Named_Attack', 5: 'Guess_passwd_Attack', 6: 'Buffer_overflow_Attack',
    7: 'UDPstorm_Attack', 8: 'Multihop_Attack', 9: 'SNMPget_Attack',
    10: 'PHF_Attack', 11: 'Worm_Attack', 12: 'Warezmaster_Attack',
    13: 'Loadmodule_Attack', 14: 'Sendmail_Attack', 15: 'Apache2_Attack',
    16: 'Land_Attack', 17: 'HTTPtunnel_Attack', 18: 'Saint_Attack',
    19: 'Teardrop_Attack', 20: 'SQL_Attack', 21: 'PS_Attack', 22: 'Satan_Attack',
    23: 'SNMPguess_Attack', 24: 'Neptune_Attack', 25: 'Smurf_Attack',
    26: 'IMAP_Attack', 27: 'Rootkit_Attack', 28: 'Portsweep_Attack',
    29: 'IPsweep_Attack', 30: 'NMAP_Attack', 31: 'Processtable_Attack',
    32: 'Mailbomb_Attack', 33: 'Xterm_Attack', 34: 'Xlock_Attack', 35: 'Back_Attack',
    36: 'FTP_Write_Attack', 37: 'No_Attack_Occurs'
}

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)''')
    conn.commit()
    conn.close()

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
            conn.commit()
            conn.close()
            return redirect(url_for('home'))
        except sqlite3.IntegrityError:
            return "Username already exists. Try a different one."
    return render_template('register.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    conn.close()
    
    if user and bcrypt.check_password_hash(user[2], password):
        session['username'] = username
        return redirect(url_for('first'))
    return "Invalid credentials. Please try again."

@app.route('/first')
def first():
    if 'username' in session:
        return render_template('first.html', username=session['username'])
    return redirect(url_for('home'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

@app.route('/predict', methods=['POST'])
def predict():
    # Collect input values from the user
    src_bytes = request.form['src_bytes']
    dst_bytes = request.form['dst_bytes']
    protocol_type = request.form['protocol_type']
    flag = request.form['flag']
    service = request.form['service']

    # Create a DataFrame for the input features
    input_data = pd.DataFrame([[src_bytes, dst_bytes, protocol_type, flag, service]], 
                              columns=['src_bytes', 'dst_bytes', 'protocol_type', 'flag', 'service'])

    # Preprocess the input data to match the training data format
    input_data = preprocess_input(input_data)

    # Make prediction using the trained model
    prediction = model.predict(input_data)[0]

    # Map the prediction to the corresponding attack type
    prediction_class = attack_type_mapping.get(prediction, 'Unknown Attack')

    # Return the prediction result to the user
    return render_template('index.html', prediction_text=f'Network Traffic is: {prediction_class}')

@app.route('/guide')
def guide_page():
    return render_template('main.html')

@app.route('/nextpage')
def next_page():
    return render_template('index.html')

def preprocess_input(input_data):
    # Define mappings with all possible values
    src_bytes_mapping = {
        'SRC_BY_BL_50': 0, 'SRC_BY_AB_100': 0, 'SRC_BY_AB_200': 0, 'SRC_BY_AB_3000': 0, 'SRC_BY_AB_700': 0,
        'SRC_BY_AB_30000': 0, 'SRC_BY_AB_8000': 0, 'SRC_BY_AB_500': 0, 'SRC_BY_AB_300': 0, 'SRC_BY_AB_1000': 0,
        'SRC_BY_AB_600': 0, 'SRC_BY_AB_900': 0, 'SRC_BY_AB_800': 0, 'SRC_BY_AB_10000': 0, 'SRC_BY_AB_2000': 0,
        'SRC_BY_AB_200000': 0, 'SRC_BY_AB_400': 0, 'SRC_BY_AB_50000': 0, 'SRC_BY_AB_5000': 0, 'SRC_BY_AB_4000': 0,
        'SRC_BY_AB_30000000': 0, 'SRC_BY_AB_7000': 0, 'SRC_BY_AB_1000000': 0, 'SRC_BY_AB_6000': 0, 'SRC_BY_AB_60000': 0,
        'SRC_BY_AB_100000': 0, 'SRC_BY_AB_500000': 0, 'SRC_BY_AB_40000': 0, 'SRC_BY_AB_9000': 0, 'SRC_BY_AB_20000': 0,
        'SRC_BY_AB_80000': 0, 'SRC_BY_AB_90000': 0, 'SRC_BY_AB_70000': 0
    }
    dst_bytes_mapping = {
        'DST_BY_BL_50': 0, 'DST_BY_AB_100': 0, 'DST_BY_AB_200': 0, 'DST_BY_AB_300': 0, 'DST_BY_AB_10000': 0,
        'DST_BY_AB_3000': 0, 'DST_BY_AB_700': 0, 'DST_BY_AB_9000': 0, 'DST_BY_AB_8000': 0, 'DST_BY_AB_600': 0,
        'DST_BY_AB_2000': 0, 'DST_BY_AB_7000': 0, 'DST_BY_AB_1000': 0, 'DST_BY_AB_4000': 0, 'DST_BY_AB_5000': 0,
        'DST_BY_AB_500': 0, 'DST_BY_AB_400': 0, 'DST_BY_AB_900': 0, 'DST_BY_AB_6000': 0, 'DST_BY_AB_300000': 0,
        'DST_BY_AB_20000': 0, 'DST_BY_AB_800': 0, 'DST_BY_AB_30000': 0, 'DST_BY_AB_60000': 0, 'DST_BY_AB_200000': 0,
        'DST_BY_AB_40000': 0, 'DST_BY_AB_50000': 0
    }
    protocol_type_mapping = {'icmp': 0, 'tcp': 0, 'udp': 0}
    flag_mapping = {'REJ': 0, 'RSTO': 0, 'RSTR': 0, 'S0': 0, 'S1': 0, 'S2': 0, 'S3': 0, 'SF': 0}
    service_mapping = {
        'private': 0, 'domain_u': 0, 'http': 0, 'smtp': 0, 'ftp_data': 0, 'ftp': 0, 'eco_i': 0, 'other': 0, 'auth': 0,
        'ecr_i': 0, 'IRC': 0, 'X11': 0, 'finger': 0, 'time': 0, 'domain': 0, 'telnet': 0, 'pop_3': 0, 'ldap': 0,
        'login': 0, 'name': 0, 'ntp_u': 0, 'http_443': 0, 'sunrpc': 0, 'printer': 0, 'systat': 0, 'tim_i': 0,
        'klogin': 0, 'imap4': 0, 'kshell': 0
    }

  # Set the selected value to 1
    src_bytes_mapping[input_data['src_bytes'][0]] = 1
    dst_bytes_mapping[input_data['dst_bytes'][0]] = 1
    protocol_type_mapping[input_data['protocol_type'][0]] = 1
    flag_mapping[input_data['flag'][0]] = 1
    service_mapping[input_data['service'][0]] = 1

    # Create new columns for each possible value of the categorical variables
    for col, mapping in [('src_bytes', src_bytes_mapping), ('dst_bytes', dst_bytes_mapping), 
                         ('protocol_type', protocol_type_mapping), ('flag', flag_mapping), ('service', service_mapping)]:
        for key in mapping.keys():
            input_data[key] = input_data[col].map(lambda x: 1 if x == key else 0)

    # Ensure the input data has the exact number of features expected by the model
    expected_features = [
        'SRC_BY_BL_50', 'SRC_BY_AB_100', 'SRC_BY_AB_200', 'SRC_BY_AB_3000', 'SRC_BY_AB_700', 'SRC_BY_AB_30000',
        'SRC_BY_AB_8000', 'SRC_BY_AB_500', 'SRC_BY_AB_300', 'SRC_BY_AB_1000', 'SRC_BY_AB_600', 'SRC_BY_AB_900',
        'SRC_BY_AB_800', 'SRC_BY_AB_10000', 'SRC_BY_AB_2000', 'SRC_BY_AB_200000', 'SRC_BY_AB_400', 'SRC_BY_AB_50000',
        'SRC_BY_AB_5000', 'SRC_BY_AB_4000', 'SRC_BY_AB_30000000', 'SRC_BY_AB_7000', 'SRC_BY_AB_1000000', 'SRC_BY_AB_6000',
        'SRC_BY_AB_60000', 'SRC_BY_AB_100000', 'SRC_BY_AB_500000', 'SRC_BY_AB_40000', 'SRC_BY_AB_9000', 'SRC_BY_AB_20000',
        'SRC_BY_AB_80000', 'SRC_BY_AB_90000', 'SRC_BY_AB_70000', 'DST_BY_AB_100', 'DST_BY_BL_50', 'DST_BY_AB_200',
        'DST_BY_AB_300', 'DST_BY_AB_10000', 'DST_BY_AB_3000', 'DST_BY_AB_700', 'DST_BY_AB_9000', 'DST_BY_AB_8000',
        'DST_BY_AB_600', 'DST_BY_AB_2000', 'DST_BY_AB_7000', 'DST_BY_AB_1000', 'DST_BY_AB_4000', 'DST_BY_AB_5000',
        'DST_BY_AB_500', 'DST_BY_AB_400', 'DST_BY_AB_900', 'DST_BY_AB_6000', 'DST_BY_AB_300000', 'DST_BY_AB_20000',
        'DST_BY_AB_800', 'DST_BY_AB_30000', 'DST_BY_AB_60000', 'DST_BY_AB_200000', 'DST_BY_AB_40000', 'DST_BY_AB_50000',
        'icmp', 'tcp', 'udp', 'REJ', 'RSTO', 'RSTR', 'S0', 'S1', 'S2', 'S3', 'SF', 'private', 'domain_u', 'http',
        'smtp', 'ftp_data', 'ftp', 'eco_i', 'other', 'auth', 'ecr_i', 'IRC', 'X11', 'finger', 'time', 'domain',
        'telnet', 'pop_3', 'ldap', 'login', 'name', 'ntp_u', 'http_443', 'sunrpc', 'printer', 'systat', 'tim_i',
        'netstat', 'remote_job', 'link', 'urp_i', 'sql_net', 'bgp', 'pop_2', 'tftp_u', 'uucp', 'imap4', 'pm_dump',
        'nnsp', 'courier', 'daytime', 'iso_tsap', 'echo', 'discard', 'ssh', 'whois', 'mtp', 'gopher', 'rje', 'ctf',
        'supdup', 'hostnames', 'csnet_ns', 'uucp_path', 'nntp', 'netbios_ns', 'netbios_dgm', 'netbios_ssn', 'vmnet',
        'Z39_50', 'exec', 'shell', 'efs', 'klogin', 'kshell', 'icmp'
    ]
    input_data = input_data.reindex(columns=expected_features, fill_value=0)

    return input_data

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
