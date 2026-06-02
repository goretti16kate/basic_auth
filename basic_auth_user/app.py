from flask import Flask,jsonify, request, render_template, make_response, redirect, url_for, session
from flask_restful import Api, Resource
from flask_httpauth import HTTPBasicAuth
from datetime import datetime, timedelta
import time
from collections import defaultdict
import json


app = Flask(__name__, template_folder='templates')
api = Api(app)
auth = HTTPBasicAuth()
app.secret_key = 'your-secret-key-here-please-change-this'

#Logs
attack_log =[]
failed_attempts = defaultdict(int)
locked_accounts = {}
rate_limit_data = defaultdict(list)


USER_DATA = {
    "user": "password",
}

@auth.verify_password
def verify(username, password):
    ip = request.remote_addr
    current_time = datetime.now()

    if username in locked_accounts:
        lock_until = locked_accounts[username]
        if current_time < lock_until:
            remaining = (lock_until - current_time).seconds // 60
            attack_log.append({
                "time": current_time.strftime("%H:%M:%S"),
                "username": username,
                "ip":ip,
                "success": False,
                "locked": True,
                "message": f"Account locked for {remaining} more minutes"
            })
            return False
        else:
            del locked_accounts[username]
            attack_log.append({
                "time": current_time.strftime("%H:%M:%S"),
                "username": username,
                "ip": ip,
                "message": "Account unlocked",
                "success": False
            })

    rate_key = f"{ip}:{username}"
    rate_limit_data[rate_key]=[t for t in rate_limit_data[rate_key] if (current_time -t).seconds< 60]

    if len(rate_limit_data[rate_key])>= 10:
        attack_log.append({
                "time": current_time.strftime("%H:%M:%S"),
                "username": username,
                "ip":ip,
                "message": f"Rate Limit exceeded! Only 10 attempts per minute allowed. Try again in {60 - (current_time - rate_limit_data[rate_key][0]). seconds} seconds",
                "success": False,

        })
        return False

    rate_limit_data[rate_key].append(current_time)



    if not (username and password):
        attack_log.append({
            "time": current_time.strftime("%H:%M:%S"),
            "username": username or "[MISSING]",
            "password": password or "[EMPTY]",
            "ip": ip,
            "success": False,
            "message": "Missing username or password"
        })
        return False
    is_valid = USER_DATA.get(username)== password

    attack_log.append({
        "time": current_time.strftime("%H:%M:%S"),
        "username": username,
        "ip": ip,
        "success": is_valid,
        "message": "Authentication successful" if is_valid else "Invalid credentials"
    })

    if not is_valid:
        failed_attempts[username] += 1
        if failed_attempts[username] >= 5:
            locked_accounts[username] = current_time + timedelta(minutes=2)
            attack_log.append({
                "time": current_time.strftime("%H:%M:%S"),
                "username": username,
                "password": "ACCOUNT_LOCKED",
                "ip": ip,
                "success": False,
                "locked": True,
                "message": "Account Locked! Too many failed attempts."
            })
    else:
        if username in failed_attempts:
            failed_attempts[username] = 0
    
    while len(attack_log) > 200:
        attack_log.pop(0)
    
    return is_valid

@app.route('/user')
@auth.login_required
def user_page():
    username = request.authorization.username
    if username == "user":
        html = render_template("user.html")
        print(f"Type before make_response: {type(html)}")
            # return jsonify({
            #     "success": True,
            #     "message": f"Welcome {username}! Good Job! The 1/3 part of the flag is in my home page /user.",
            # })
        response = make_response(html)
        print(f"Type after make_response: {type(response)}")
        return response
    return jsonify({
            "message": "This endpoint requires credentials"}), 401



class endpoint(Resource):
    @auth.login_required
    def get(self):
        return jsonify({"status": True, "message": "Authentication successful"})

    def options(self):
        return jsonify({"status": "ok"})

class Dashboard(Resource):
    def get(self):
        total = len(attack_log)
        successful = sum(1 for a in attack_log if a['success'])
        failed = total - successful
        
        html = render_template("dashboard.html", 
                             stats={
                                 'total': total,
                                 'successful': successful,
                                 'failed': failed
                             },
                             attempts=attack_log[-20:],
                             failed_counts=dict(failed_attempts))
        response = make_response(html)
        return response
        



api.add_resource(endpoint, "/endpoint")
api.add_resource(Dashboard, "/", "/dashboard")


if __name__=="__main__":
    app.run(port=5000, debug=True, host='0.0.0.0')
