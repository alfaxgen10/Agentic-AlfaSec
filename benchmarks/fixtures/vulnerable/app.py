import os
import subprocess
import sqlite3

from flask import request

def run():
    value = request.args["cmd"]
    subprocess.run(value, shell=True)
    query = "SELECT * FROM users WHERE name = '" + request.args["name"] + "'"
    sqlite3.connect("app.db").execute(query)
