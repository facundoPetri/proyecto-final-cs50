import os
import requests
import urllib.parse

from flask import redirect, render_template, request, session
from functools import wraps


def apology(message, code=400):
    """Render message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code


def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/1.0/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


def parse(response):
        data = response.json()
        if data["type"] == "twopart":
            return {
                "type": data["type"],
                "setup": data["setup"],
                "delivery": data["delivery"],
                "id": data["id"]
            }
        else:
            return {
                "type": data["type"],
                "joke": data["joke"],
                "id": data["id"]
            }


def getJoke(req_id = -1):
    if req_id == -1:
        response = requests.get("https://sv443.net/jokeapi/v2/joke/Any")

        final = parse(response)
        return final
    else:
        response = requests.get(f"https://sv443.net/jokeapi/v2/joke/Any?idRange={req_id}")

        final = parse(response)
        return final


