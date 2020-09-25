import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import login_required, apology, getJoke

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///anyjoke.db")


@app.route("/", methods=["GET", "POST"])
@login_required
def index():

    # Query database and select the id of the jokes that the current user saved
    myJokes = db.execute("SELECT joketext FROM favorites WHERE user_id = :user_id", user_id=session["user_id"])

    if request.method == "POST":
        joketext = request.form.get("remove")

        db.execute("DELETE FROM favorites WHERE joketext = :joketext AND user_id = :user_id", joketext=joketext, user_id=session["user_id"])

        flash("Joke eliminated from favorites!")
        return redirect("/")
    else:
        return render_template("index.html", myJokes=myJokes)


@app.route("/joke", methods=["GET", "POST"])
@login_required
def joke():
    # Call the api for random joke
    joke = getJoke()
    jokeCombined = ""
    # Link the two parts of the joke in one string
    if joke["type"] == "twopart":
        jokeCombined = joke["setup"] + " " + joke["delivery"]

     # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # User clicked the "Save joke" button in the front end
        if request.form["submit_button"] == "Save joke":

            # Query for the id of the jokes the user saved
            usersJokes = db.execute("SELECT joke_id FROM favorites WHERE user_id = :user_id", user_id=session["user_id"])

            # Iterate over the jokes the user saved
            for userJoke in usersJokes:

                # Ensure if the user already saved that joke
                if userJoke["joke_id"] == request.form.get("id"):
                    return apology("joke already in favorites", 400)

            # Update the db to add the new id of the joke the user liked
            db.execute("INSERT INTO favorites (user_id, joke_id, joketext) VALUES(:user_id, :joke_id, :joketext)", user_id=session["user_id"], joke_id=request.form.get("id"), joketext=request.form.get("joketext"))

        # User clicked the "Get another one" button in the front end
        else:
            return render_template("joke.html", joke=joke, jokeCombined=jokeCombined)

        # Flash message of success
        flash("Joke saved!")

        # Prompt a new random joke
        return render_template("joke.html", joke=joke, jokeCombined=jokeCombined)

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("joke.html", joke=joke, jokeCombined=jokeCombined)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        flash("You have been logged in!")
        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    if request.method == "POST":

        oldPassword = request.form.get("oldpassword")
        newPassword = request.form.get("newpassword")

        # Check if the username is empty
        if not oldPassword:
            return apology("must provide username", 403)

        # Check if the password is empty
        elif not newPassword:
            return apology("must provide a password", 403)

        # Check if the password doesnt match
        elif request.form.get("confirmation") != newPassword:
            return apology("password and confirmation must match", 403)

        # Query database for password
        rows = db.execute("SELECT hash FROM users WHERE id = :user_id", user_id=session["user_id"])

        # Ensure password is correct
        if not check_password_hash(rows[0]["hash"], oldPassword):
            return apology("invalid password", 403)

        # Hash new password
        passwordHash = generate_password_hash(newPassword)

        # Update database
        db.execute("UPDATE users SET hash = :hash WHERE id = :user_id", hash=passwordHash, user_id=session["user_id"])

        flash("You have changed your password succesfully!")
        return redirect("/")
    else:
        return render_template("change.html")


@app.route("/addfriend", methods=["GET", "POST"])
@login_required
def addfriend():
    if request.method == "POST":
        username = request.form.get("username")

        # Query database for username
        rows = db.execute("SELECT username, id FROM users WHERE username = :username", username=username)

        # Ensure username exists
        if len(rows) != 1 or not username:
            return apology("enter a valid username", 400)

        # Insert user into friends table
        db.execute("INSERT INTO friends (user_id, friend_id) VALUES(:user_id, :friend_id)", user_id=session["user_id"], friend_id=rows[0]["id"])

        flash("Friend added!")
        return render_template("addfriend.html")
    else:
        return render_template("addfriend.html")


@app.route("/friends")
@login_required
def friends():
    myFriendsId = db.execute("SELECT friends.friend_id, users.username FROM friends JOIN users ON  users.id = friends.user_id WHERE user_id = :user_id", user_id=session["user_id"])
    jokes = []
    total = []
    for i in myFriendsId:
        joke = db.execute("SELECT joketext FROM favorites WHERE user_id = :friend_id", friend_id=i["friend_id"])
        name = db.execute("SELECT username FROM users WHERE users.id = :friend_id", friend_id=i["friend_id"])
        for j in joke:
            jokes.append(j["joketext"])
        myDict = {
            "username": name[0]["username"],
            "jokes": jokes
        }
        total.append(myDict)
        jokes = []

    return render_template("friends.html", total=total)

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()
    flash("You have been logged out!")
    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":

        # Save the username and password the user typed in 2 variables
        username = request.form.get("username")
        password = request.form.get("password")

        # Check if the username is empty
        if not username:
            return apology("must provide username", 403)

        # Check if the password is empty
        elif not password:
            return apology("must provide a password", 403)

        # Check if the password doesnt match
        elif request.form.get("confirmation") != password:
            return apology("password and confirmation must match", 403)

        # Check if username is already taken
        totalUsers = db.execute("SELECT username FROM users")
        for user in totalUsers:
            if user["username"] == username:
                return apology("name already in use", 403)

        # Hash the password
        passwordHash = generate_password_hash(password)

        # Insert the new user into the database
        db.execute("INSERT INTO users (username, hash) VALUES(:username, :hash)", username=username, hash=passwordHash)

        flash("You have registered succesfully")
        return redirect("/")

    else:
        return render_template("register.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
