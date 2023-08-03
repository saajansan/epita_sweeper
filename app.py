from flask import Flask, render_template, request, redirect, url_for
import xml.etree.ElementTree as ET
import bcrypt
import sys
import os
import magic
import time
import full4
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

@app.route('/all-files', methods=['GET'])
def allFiles():
    files = get_files('./uploads')
    return render_template('files.html', data=files)


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
                   # return render_template('files.html', data=files)
                   return redirect(url_for('allFiles'))
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
    # Perform scanning and analysis on the selected files
    checkbox_values = request.form.getlist('files[]')
    result_messages = {}
    for file_path in checkbox_values:
        # Perform your scanning and analysis operations here
        print(file_path)    # Redirect or render a response after the scanning process is complete
        full4.clamav_scan(file_path)
        full4.yara_check(file_path)
        full4.pdf_analysis(file_path)
        all_file_messages = full4.all_file_messages
        result_messages[os.path.basename(file_path)] = all_file_messages
        full4.all_file_messages = {
            "clamav_scan": "",
            "yara_check": "",
        }
        #return "Scanning process completed."
    all_messages = full4.all_messages
    full4.all_messages = []
    return render_template('scan-results.html', messages=all_messages, result_messages=result_messages)
if __name__ == '__main__':
    app.run(debug=True)


