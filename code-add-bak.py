from flask import Flask, render_template, request, redirect, url_for
import xml.etree.ElementTree as ET
import bcrypt
import sys
import os
import magic
import time
import pyclamd
import yara
import PyPDF2
# generate a salt value
salt = bcrypt.gensalt(12)

# hash the password using the salt value
# password = 'test123'.encode('utf-8')
# hashed_password = bcrypt.hashpw(password, salt)

from lxml import etree

def parse_users_xml():
    tree = etree.parse('users.xml')
    users = []
    for user_elem in tree.xpath('/users/user'):
        user = {
            'username': user_elem.xpath('username/text()')[0],
            'password': user_elem.xpath('password_hash/text()')[0]
        }
        users.append(user)
    return users


def get_files(path):
     # specify the folder path
    folder_path = path

    # get a list of all files in the folder
    files = os.listdir(folder_path)

    # loop through the files and create a dictionary for each file
    file_dicts = []
    for file in files:
        file_path = os.path.join(folder_path, file)
        file_dict = {}
        file_dict['name'] = file
        file_dict['path'] = file_path
        file_dict['size'] = os.path.getsize(file_path)
        file_dict['created'] = time.ctime(os.path.getctime(file_path))
        file_dict['modified'] = time.ctime(os.path.getmtime(file_path))
        file_dict['abs_path'] = os.path.abspath(file_path)
        file_dicts.append(file_dict)

    # print the list of dictionaries
    return file_dicts
app = Flask(__name__)
users = parse_users_xml()

@app.route('/addNewuser')
def addNewuser():
    return render_template('addNewuser.html')

# Define route to handle form submissions
@app.route('/submit', methods=['POST'])
def submit():
    # Get form data
    name = request.form['name']
    email = request.form['email']
    password = request.form['password']

    # Hash password using bcrypt
    salt = bcrypt.gensalt(12)
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    print(hashed_password, file=sys.stderr)
    print(type(hashed_password), file=sys.stderr)
                
    # Create XML element for new user
    user = ET.Element("user")
    username = ET.SubElement(user, "username")
    username.text = name
    email_address = ET.SubElement(user, "email")
    email_address.text = email
    password_hash = ET.SubElement(user, "password_hash")
    password_hash.text = hashed_password.decode('ascii')

    # Add new user to XML file
    tree = ET.parse('users.xml')
    root = tree.getroot()
    root.append(user)
    tree.write('users.xml')

    # Redirect to success page
    return redirect(url_for('success'))

# Define route for success page
@app.route('/success')
def success():
     return render_template('success.html')


@app.route('/filelist', methods=[ 'POST'])
def filelist():
        # print("hai", file=sys.stderr)
        files = get_files('./uploads')
        # print(files)
        # return render_template('files.html', data=files)
        username = request.form['username']
        password = request.form['password']
        hashed =   bcrypt.hashpw(password.encode('utf-8'),salt)
        users = parse_users_xml()
        for user in users:
             print(user, file=sys.stderr)
        for user in users:
            print(user['username'],username, file=sys.stderr)

            if   user['username'].__eq__(username):
                print("correct pass", file=sys.stderr)
                
                try:
                    print("db",user['password'].encode("ascii"), file=sys.stderr)
                    print("new",hashed, file=sys.stderr)
                except KeyError:
                    print("Email key does not exist in the user dictionary.", file=sys.stderr)
                if bcrypt.checkpw(password.encode('ascii'), user['password'].encode('ascii')):
                   return render_template('files.html', data=files)
                else:
                    return 'Incorrect password!' 
        return 'User not found! Please Create New User to login or contact adiministrator'

@app.route('/', methods=['GET'])
def login_submit():
        return render_template('index.html')

@app.route('/about/')
def about():
    return render_template('about.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        # Get the uploaded file from the form
        pdf_file = request.files['pdf_file']

        # Validate file extension
        if not pdf_file.filename.endswith('.pdf'):
            return render_template('upload.html', error='Invalid file format. Please upload a PDF file.')

        # Validate file size
        max_size = 5 * 1024 * 1024  # 5 MB
        if len(pdf_file.read()) > max_size:
            return render_template('upload.html', error='File size exceeds the limit. Please upload a file up to 5 MB.')

        # Reset file cursor to the beginning for saving
        pdf_file.seek(0)

        # Validate file content using magic module
        file_content = pdf_file.read()
        mime_type = magic.from_buffer(file_content, mime=True)
        if mime_type != 'application/pdf':
            return render_template('upload.html', error='Invalid file format. Please upload a valid PDF file.')

        # Save the file to a specific folder
        upload_folder = './uploads'  # Replace with the desired folder path
        pdf_file.seek(0)
        pdf_file.save(os.path.join(upload_folder, pdf_file.filename))

        # Redirect to the scanning page
        return redirect(url_for('success'))

    # If it's a GET request, render the upload page
    return render_template('upload.html')
@app.route('/scan', methods=['POST'])
def scan():
    # Retrieve the selected files from the form submission
    selected_files = request.form.getlist('files[]')
    
    # Perform scanning and analysis on the selected files
    for file_path in selected_files:
        # Perform your scanning and analysis operations here
        
    # Redirect or render a response after the scanning process is complete
        return "Scanning process completed."



# Connect to ClamAV daemon
try:
    cd = pyclamd.ClamdUnixSocket()
except pyclamd.ConnectionError as e:
    print(f"ClamAV connection error: {e}")
    exit(1)

# Load YARA rules
yara_rules = yara.compile('pdf_rules.yar')

# Path to the PDF file
pdf_file_path = 'path/to/your/pdf/file.pdf'

# Function to perform ClamAV scan
def clamav_scan(file_path):
    with open(file_path, 'rb') as f:
        file_contents = f.read()

    result = cd.scan_stream(file_contents)

    if result is None:
        print(f'{file_path} is clean')
    elif file_path in result:
        if result[file_path][0] == 'OK':
            print(f'{file_path} is clean')
    else:
        print(f'Scan result: {result} in {file_path}')

# Function to perform YARA check
def yara_check(file_path):
    matches = yara_rules.match(file_path)
    if matches:
        print(f'{file_path} matches YARA rule(s): {matches}')
    else:
        print(f'{file_path} does not match any YARA rule')

# Open the PDF file
with open(pdf_file_path, 'rb') as file:
    # Create a PDF reader object
    reader = PyPDF2.PdfReader(file)

    # Perform ClamAV scan
    clamav_scan(pdf_file_path)

    # Perform YARA check
    yara_check(pdf_file_path)

# Load YARA rules
yara_rules = yara.compile('pdf_rules.yar')

app = Flask(__name__)

@app.route('/check_pdf', methods=['POST'])
def check_pdf():
    # Get the uploaded PDF file from the form
    pdf_file = request.files['pdf_file']
    
    # Save the PDF file to a temporary location
    temp_file_path = '/path/to/temp/file.pdf'
    pdf_file.save(temp_file_path)

    # Function to perform YARA check
    def yara_check(file_path):
        matches = yara_rules.match(file_path)
        if matches:
            return f'{file_path} matches YARA rule(s): {matches}'
        else:
            return None

    # Perform YARA check on the PDF file
    error_message = yara_check(temp_file_path)

    # Render the appropriate template based on the presence of an error
    if error_message:
        return render_template('error.html', error_message=error_message)
    else:
        return render_template('success.html')
    

if __name__ == '__main__':
    app.run(debug=True)


