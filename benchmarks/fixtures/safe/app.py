import sqlite3

def run(name):
    connection = sqlite3.connect("app.db")
    connection.execute("SELECT * FROM users WHERE name = ?", (name,))
