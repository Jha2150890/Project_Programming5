# Jhae Moore
# CIS256 Fall 2024
# Programming Assignment 5 (PA 5)

from flask import Flask, request, render_template_string
from flask_bcrypt import Bcrypt
import re

app = Flask(__name__)
bcrypt = Bcrypt(app)


@app.route('/login')
def login_form():
    form_html = '''
    <form method="POST" action="/login">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username">
        <label for="password">Password:</label>
        <input type="password" id="password" name="password">
        <input type="submit" value="Login">
    </form>
    '''
    return render_template_string(form_html)


@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    if len(username) >= 5:  # Username must be at least 5 characters
        if re.match(r'^[A-Za-z0-9_]+$',
                    username):  # Username accept letters, numbers, and underscore(_). Does not allow other special characters.
            if len(password) >= 8:  # Password must be at least 8 characters long
                if password.isalnum():  # Password must contain letters and/or numbers
                    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')  # Hash the password
                    pass_valid = bcrypt.check_password_hash(hashed_password,
                                                            password)  # Compare the regular password and hashed password to check if they're the same.
                    if pass_valid:  # If regular password and hashed password are the same, the username and password will be displayed.
                        return f'Username: {username}, Password: {password}'
                else:
                    return "Password must not contain any special characters or white spaces"
            else:
                return "Password must be at least 8 characters"
        else:
            return "Username must not contain special characters (except underscores) or white spaces"
    else:
        return "Username must be at least 5 characters"


if __name__ == '__main__':
    app.run(debug=True)
