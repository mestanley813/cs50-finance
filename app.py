import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    stocks = db.execute("SELECT * FROM portfolio WHERE id = ?", session["user_id"])
    cashBalance = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    cashBalance = cashBalance[0]["cash"]
    sum = cashBalance

    for stock in stocks:
        currentStock = lookup(stock['symbol'])
        stock['name'] = currentStock['name']
        stock['price'] = currentStock['price']
        stock['total'] = currentStock['price'] * stock['shares']

        sum += stock['total']

        stock['price'] = usd(stock['price'])
        stock['total'] = usd(stock['total'])

    return render_template("index.html", stocks=stocks, cashBalance=usd(cashBalance), sum=usd(sum))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    print(session["user_id"])

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        stock = lookup(request.form.get("symbol"))
        if not stock:
            return apology("Could not find stock", 400)

        symbol = stock["symbol"]
        price = stock["price"]
        shares = request.form.get("shares")

        # Check for valid input
        if stock["symbol"] == "" or stock == None:
            return apology("Could not find stock", 400)
        elif not shares.isnumeric():
            return apology("Shares must be whole numbers and numeric characters", 400)
        shares = int(shares)
        if shares < 1:
            return apology("Shares must be greater than 0", 400)

        else:
            cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
            cash = cash[0]["cash"]

            # Check if user can afford the stocks
            if (cash < price * float(shares)):
                return apology("You cannot afford these shares at the current price")

            # Keep track of the stocks that the user owns
            cash = cash - price * float(shares)

            # Check if stock is already in table
            existingShares = db.execute("SELECT shares FROM portfolio WHERE id = ? AND symbol = ?", session["user_id"], symbol)

            if not existingShares:
                db.execute("INSERT INTO portfolio (id, symbol, shares, bought_price) VALUES (?, ?, ?, ?)",
                           session["user_id"], symbol, shares, price)

            else:
                existingShares = existingShares[0]['shares']
                shares += existingShares
                db.execute("UPDATE portfolio SET shares = ? WHERE id = ? AND symbol = ?", shares, session["user_id"], symbol)
            db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, session["user_id"])
            db.execute("INSERT INTO history (id, symbol, shares, price, method) VALUES (?, ?, ?, ?, ?)",
                       session["user_id"], symbol, shares, usd(price), "BUY")

            flash('Bought!')
            return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    history = db.execute("SELECT * from history WHERE id = ?", session["user_id"])
    return render_template("history.html", history=history)


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/reset", methods=["GET", "POST"])
@login_required
def reset():
    "Reset user's password"
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure old password, new password, and confirmation were submitted
        if not request.form.get("oldPassword") or not request.form.get("newPassword") or not request.form.get("confirmation"):
            return apology("All fields must be input", 403)
        # Ensure password and confirmation match
        elif not request.form.get("newPassword") == request.form.get("confirmation"):
            return apology("passwords do not match", 403)

        # Generate the old password
        hash = db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"])
        hash = hash[0]['hash']

        # Ensure old password matches the hash
        if not check_password_hash(hash, request.form.get("oldPassword")):
            return apology("old password is incorrect", 403)

        # Hash new password and replace the old one in the database
        hash = generate_password_hash(request.form.get("newPassword"))
        db.execute("UPDATE users set hash = ? WHERE id = ?", hash, session["user_id"])

        flash('Your password has been reset!')
        return redirect("/logout")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("reset.html")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("You must fill out the symbol field to get a quote", 400)
        stock = lookup(request.form.get("symbol"))
        if not stock:
            return apology("Could not find stock symbol", 400)
        return render_template("quoted.html", name=stock["name"], price=stock["price"], symbol=stock["symbol"])

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username, password, and confirmation were submitted
        if not request.form.get("username") or not request.form.get("password") or not request.form.get("confirmation"):
            return apology("all fields must be input", 400)

        # Ensure password and confirmation match
        elif not request.form.get("password") == request.form.get("confirmation"):
            return apology("passwords do not match", 400)

        # Ensure username is not already taken
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        if len(rows) != 0:
            return apology("username already exists", 400)

        # Add user to the database
        username = request.form.get("username")
        hash = generate_password_hash(request.form.get("password"))
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)

        # Log the newly registered user in
        rows = db.execute("SELECT id FROM users WHERE username = ?", username)
        session["user_id"] = rows[0]['id']
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        stocks = db.execute("SELECT * FROM portfolio WHERE id = ? AND symbol = ?", session["user_id"], symbol)

        # Check for errors
        if symbol == "":
            return apology("You must input a symbol in order to sell", 400)
        elif len(stocks) != 1:
            return apology("You must own this stock in order to sell", 400)
        elif not shares:
            return apology("You must provide a number of shares to sell", 400)

        shares = int(shares)
        if shares > stocks[0]['shares']:
            return apology("You do not own enough shares to sell this many", 400)

        # Sell the shares
        currentPrice = lookup(symbol)
        currentPrice = currentPrice['price']
        oldShares = stocks[0]['shares']
        liquidation = currentPrice * shares

        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        cash = cash[0]['cash']
        cash = cash + liquidation
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, session["user_id"])

        # Update shares in the porfolio
        db.execute("INSERT INTO history (id, symbol, shares, price, method) VALUES (?, ?, ?, ?, ?)",
                   session["user_id"], symbol, -(shares), usd(currentPrice), "SELL")

        shares = oldShares - shares
        if shares > 0:
            db.execute('UPDATE portfolio SET shares = ? WHERE id = ? AND symbol = ?', shares, session["user_id"], symbol)
        else:
            db.execute('DELETE FROM portfolio WHERE id = ? AND symbol = ?', session["user_id"], symbol)
        flash('Sold!')
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        stocks = db.execute("SELECT * FROM portfolio WHERE id = ?", session["user_id"])
        return render_template("sell.html", stocks=stocks)