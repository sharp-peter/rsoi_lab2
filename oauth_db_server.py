from flask import Flask, request, render_template, redirect
from datetime import datetime, timedelta

import json
import math
import os
import uuid

import sqlite3

app = Flask(__name__)

# Server database (on sqlite3)
db = sqlite3.connect('server_database.db', check_same_thread=False)
cursor = db.cursor()

# User registration
@app.route('/register', methods=['GET','POST'])
def register():
	if request.method == 'GET':
		return render_template('registration_page.html')
	
	username = request.form['username']
	firstname = request.form['firstname']
	lastname = request.form['lastname']
	
	email = request.form['email']
	phone = request.form['phone']
	password = request.form['password']
	
	cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
	user = cursor.fetchone()
	
	if (user is not None):
		return render_template('registration_error.html', reason = 'Username already exists')
	
	cursor.execute("INSERT INTO users VALUES (?,?,?,?,?,?)", (username, firstname, lastname, email, phone, password))
	db.commit()
	
	return render_template('registration_success.html')

# OAuth 2.0 authorization
@app.route('/oauth/authorize', methods=['GET','POST'])
def authorize():
	if request.method == 'GET':
		response_type = request.args.get('response_type', None)
		client_id = request.args.get('client_id', None)
		state = request.args.get('state', None)
		
		cursor.execute("SELECT * FROM clients WHERE client_id = ?", (client_id,))
		client = cursor.fetchone()
				
		if (client is None):
			return render_template('authorization_error.html', reason='Invalid client ID.')
		
		if response_type != 'code':
			return redirect(client[2] + '?error=unsupported_response_type' +('' if state is None else '&state=' + state), code=302)
		
		return render_template('authorization_page.html', state=state, client_id=client_id)
	
	client_id = request.form.get('client_id')
	username = request.form.get('username')
	password = request.form.get('password')
	state = request.form.get('state', None)
	
	cursor.execute("SELECT * FROM clients WHERE client_id = ?", (client_id,))
	client = cursor.fetchone()
	
	cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
	user = cursor.fetchone()
	
	if (user is None) or (user[5] != password):
		return redirect(client[2] + '?error=access_denied' + ('' if state is None else '&state=' + state), code=302)
	
	code = uuid.uuid4().hex
	cursor.execute("INSERT INTO authorization VALUES (?,?,?)", (user[0], code, datetime.now() + timedelta(seconds=600)))
	db.commit()
	
	return redirect(client[2] + '?code=' + code + ('' if state is None else '&state=' + state), code=302)
	
# Returns JSON-response with given error (malformed request)
def token_error_json(error):
	return json.dumps({'error': error}), 400, {
		'Content-Type': 'application/json;charset=UTF-8',		 
	}

# Access and refresh token generation
def token_generate(username):
	access_token = uuid.uuid4().hex
	refresh_token = uuid.uuid4().hex
	access_expiration = datetime.now() + timedelta(seconds=3600)
	
	cursor.execute("INSERT INTO tokens VALUES(?,?,?,?)", (username, access_token, refresh_token, access_expiration))
	db.commit()
	
	return (access_token, refresh_token)

# OAuth 2.0 access and refresh token handout
@app.route('/oauth/token')
def token_handout():
	try:
		grant_type = request.form.get('grant_type')
		client_id = request.form.get('client_id')
		client_secret = request.form.get('client_secret')
	except KeyError:
		return token_error_json('invalid_request')
	
	cursor.execute("SELECT client_secret FROM clients WHERE client_id = ?", (client_id,))
	client_sc = cursor.fetchone()
	
	if client_sc[0] != client_secret:
		return token_error_json('invalid_client')

	if grant_type == 'authorization_code':
		try:
			code = request.form.get('code')
		except KeyError:
			return token_error_json('invalid_request')

		cursor.execute("SELECT * FROM authorization WHERE code = ?", (code,))
		authorization = cursor.fetchone()

		if (authorization is None) or (datetime.strptime(authorization[2], "%Y-%m-%d %H:%M:%S.%f") < datetime.now()):
			return token_error_json('invalid_grant')
			
		username = authorization

		cursor.execute("DELETE FROM authorization WHERE code = ?", (code,))
		db.commit()
	elif grant_type == 'refresh_token':
		try:
			refresh_token = request.form.get('refresh_token')
		except KeyError:
			return token_error_json('invalid_request')
		
		cursor.execute("SELECT username FROM tokens WHERE refresh_token = ?", (refresh_token,))
		username = cursor.fetchone()
		
		if (username is None):
			return token_error_json('invalid_grant')
		
		cursor.execute("DELETE FROM tokens WHERE refresh_token = ?", (refresh_token,))
		db.commit()
	else:
		return token_error_json('unsupported_grant_type')

	access_token, refresh_token = token_generate(username[0])
	
	return json.dumps({
		'access_token': access_token,
		'token_type': 'bearer',
		'expires_in': 3600,
		'refresh_token': refresh_token,
	}), 200, {
		'Content-Type': 'application/json;charset=UTF-8',
		'Cache-Control': 'no-store',
		'Pragma': 'no-cache',
	}

# Checking if access token is valid
def acc_token_checkout(access_token):
	cursor.execute("SELECT access_expiration FROM tokens WHERE access_token = ?", (access_token,))
	exp_time = cursor.fetchone()
	
	if (exp_time is None):
		return False
	
	if (datetime.strptime(exp_time[0], "%Y-%m-%d %H:%M:%S.%f") < datetime.now()):
		return False
		
	return True

# Information about user (closed method)
@app.route('/me')
def user_info():
	access_token = request.headers.get('Authorization', '')[len('Bearer '):]
	if not acc_token_checkout(access_token):
		return '', 403
		
	cursor.execute("SELECT username FROM tokens WHERE access_token = ?", (access_token,))
	username = cursor.fetchone()
	cursor.execute("SELECT * FROM users WHERE username = ?", (username[0],))
	user_info = cursor.fetchone()
	
	return json.dumps({
		'username': user_info[0],
		'firstname': user_info[1],
		'lastname': user_info[2],
		'email': user_info[3],
		'phone': user_info[4],
		'password': user_info[5]
	}, indent=4), 200, {
		'Content-Type': 'application/json;charset=UTF-8'
	}

# Get a list of all employees by page (open method)
@app.route('/personnel')
def get_personnel():
	per_page = int(request.args.get('per_page'))
	page = int(request.args.get('page'))
	
	personnel = []
	for employee in cursor.execute("SELECT * FROM personnel LIMIT ?, ?", (page*per_page, per_page)):
		personnel.append({
			'id': employee[0],
			'firstname': employee[1],
			'lastname': employee[2],
			'hiredate': employee[3],
			'occupation':employee[4]
		})
	
	return json.dumps({
		'personnel': personnel,
		'per_page': per_page,
		'page': page,
		'page_count': math.ceil(len(personnel) / per_page)
	}, indent=4), 200, {
		'Content-Type': 'application/json;charset=UTF-8',		 
	}

# Get information about employee by ID (closed method)
@app.route('/personnel/<int:item_id>', methods=['GET'])
def get_employee(item_id):
	access_token = request.headers.get('Authorization', '')[len('Bearer '):]
	if not acc_token_checkout(access_token):
		return '', 403
	
	cursor.execute("SELECT * FROM personnel WHERE id = ?", (item_id,))
	employee = cursor.fetchone()
	
	return json.dumps({
		'id': employee[0],
		'firstname': employee[1],
		'lastname': employee[2],
		'hiredate': employee[3],
		'occupation':employee[4]
	}, indent=4), 200, {
		'Content-Type': 'application/json;charset=UTF-8'
	}

# Add new employee by ID (closed method)
@app.route('/personnel/<int:item_id>', methods=['POST'])
def post_personnel(item_id):
	access_token = request.headers.get('Authorization', '')[len('Bearer '):]
	if not acc_token_checkout(access_token):
		return '', 403
	
	cursor.execute("SELECT * FROM personnel WHERE id = ?", (item_id,))
	employee = cursor.fetchone()
	
	if (employee is not None):
		return '', 409
	
	newempl = request.json
	cursor.execute("SELECT * FROM departments WHERE id = ?", (newempl['occupation'],))
	department = cursor.fetchone()
	
	if (department is None):
		return '', 400
	
	cursor.execute("INSERT INTO personnel VALUES (?,?,?,?,?)", (item_id, newempl['firstname'], newempl['lastname'], newempl['hiredate'], newempl['occupation']))
	db.commit()
	
	return '', 201, {
		'Location': '/personnel/{}'.format(item_id),
		'Content-Type': 'application/json;charset=UTF-8'
	}

# Edit information about employee by ID (closed method)
@app.route('/personnel/<int:item_id>', methods=['PUT'])
def put_personnel(item_id):
	access_token = request.headers.get('Authorization', '')[len('Bearer '):]
	if not acc_token_checkout(access_token):
		return '', 403
	
	cursor.execute("SELECT * FROM personnel WHERE id = ?", (item_id,))
	employee = cursor.fetchone()
	
	if (employee is None):
		return '', 404
	
	newempl = request.json
	cursor.execute("SELECT * FROM departments WHERE id = ?", (newempl['occupation'],))
	department = cursor.fetchone()
	
	if (department is None):
		return '', 400
	
	cursor.execute("UPDATE personnel SET firstname = ?, lastname = ?, hiredate = ?, occupation = ? WHERE id = ?", (newempl['firstname'], newempl['lastname'], newempl['hiredate'], newempl['occupation'], item_id))
	db.commit()
	
	return '', 200

# Delete an employee by ID (closed method)
@app.route('/personnel/<int:item_id>', methods=['DELETE'])
def delete_personnel(item_id):
	access_token = request.headers.get('Authorization', '')[len('Bearer '):]
	if not acc_token_checkout(access_token):
		return '', 403
	
	cursor.execute("SELECT * FROM personnel WHERE id = ?", (item_id,))
	employee = cursor.fetchone()
	
	if (employee is None):
		return '', 404
	
	cursor.execute("DELETE FROM personnel WHERE id = ?", (item_id,))
	db.commit()
	
	return '', 200

# Get a list of departments by page (open method)
@app.route('/departments')
def get_departments():
	per_page = int(request.args.get('per_page'))
	page = int(request.args.get('page'))
	
	departments = []
	for department in cursor.execute("SELECT * FROM departments LIMIT ?, ?", (page*per_page, per_page)):
		departments.append({
			'id': department[0],
			'name': department[1],
			'location': department[2],
			'email': department[3]
		})
	
	return json.dumps({
		'departments': departments,
		'per_page': per_page,
		'page': page,
		'page_count': math.ceil(len(departments) / per_page)
	}, indent=4), 200, {
		'Content-Type': 'application/json;charset=UTF-8'
	}

# Get information about department by ID (closed method)
@app.route('/departments/<int:class_id>', methods=['GET'])
def get_department(class_id):
	access_token = request.headers.get('Authorization', '')[len('Bearer '):]
	if not acc_token_checkout(access_token):
		return '', 403
	
	cursor.execute("SELECT * FROM departments WHERE id = ?", (class_id,))
	department = cursor.fetchone()
	
	personnel = []
	for employee in cursor.execute("SELECT * FROM personnel where occupation = ?", (class_id,)):
		personnel.append({
			'id': employee[0],
			'firstname': employee[1],
			'lastname': employee[2],
			'hiredate': employee[3]
		})
	
	return json.dumps({
		'id': department[0],
		'name': department[1],
		'location': department[2],
		'email': department[3],
		'personnel': personnel
	}, indent=4), 200, {
		'Content-Type': 'application/json;charset=UTF-8'
	}

# Add new department by ID (closed method)
@app.route('/departments/<int:class_id>', methods=['POST'])
def post_department(class_id):
	access_token = request.headers.get('Authorization', '')[len('Bearer '):]
	if not acc_token_checkout(access_token):
		return '', 403
	
	cursor.execute("SELECT * FROM departments WHERE id = ?", (class_id,))
	department = cursor.fetchone()
	
	if (department is not None):
		return '', 409
	
	newdprt = request.json
	cursor.execute("INSERT INTO departments VALUES (?,?,?,?)", (class_id, newdprt['name'], newdprt['location'], newdprt['email']))
	db.commit()
	
	return '', 201, {
		'Location': '/departments/{}'.format(class_id),
		'Content-Type': 'application/json;charset=UTF-8'
	}

# Edit information about department by ID (closed method)
@app.route('/departments/<int:class_id>', methods=['PUT'])
def put_department(class_id):
	access_token = request.headers.get('Authorization', '')[len('Bearer '):]
	if not acc_token_checkout(access_token):
		return '', 403
	
	cursor.execute("SELECT * FROM departments WHERE id = ?", (class_id,))
	department = cursor.fetchone()
	
	if (department is None):
		return '', 404
	
	newdprt = request.json
	cursor.execute("UPDATE departments SET name = ?, location = ?, email = ? WHERE id = ?", (newdprt['name'], newdprt['location'], newdprt['email'], class_id))
	db.commit()
	
	return '', 200

# Delete a department by ID (closed method)
@app.route('/departments/<int:class_id>', methods=['DELETE'])
def delete_department(class_id):
	access_token = request.headers.get('Authorization', '')[len('Bearer '):]
	if not acc_token_checkout(access_token):
		return '', 403
	
	cursor.execute("SELECT * FROM departments WHERE id = ?", (class_id,))
	department = cursor.fetchone()
	
	if (department is None):
		return '', 404
	
	cursor.execute("SELECT * FROM personnel WHERE occupation = ?", (class_id,))
	personnel = cursor.fetchone()
	
	if (personnel is not None):
		return '', 405
	
	cursor.execute("DELETE FROM departments WHERE id = ?", (class_id,))
	db.commit()
	
	return '', 200

def main():
	app.run(port = 5050, debug = True)
	
if __name__ == '__main__':
	main()