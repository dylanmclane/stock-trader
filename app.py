import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import login_required, lookup, usd

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

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    """Show portfolio of stocks"""
    # current user's username and cash
    current_user = db.execute(
        "SELECT username, cash FROM users WHERE id = ?;", session["user_id"]
    )
    if len(current_user) > 0:
        current_user = current_user[0]
    else:
        return redirect("/")

    grand_total = int(current_user["cash"])

    # current user's stocks and shares
    stock_info = db.execute(
        "SELECT SUM(shares) AS tot_shares, stock  FROM purchases WHERE user = ? GROUP BY(stock) HAVING tot_shares > 0;",
        current_user["username"],
    )

    for stock in stock_info:
        lookup_stock = lookup(stock["stock"])
        stock["price"] = lookup_stock["price"]
        stock["tot_value"] = usd(stock["price"] * stock["tot_shares"])
        grand_total += stock["price"] * stock["tot_shares"]

    # code for buying already owned shares 
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        shares = int(shares)

        for stock in stock_info:
            if stock["stock"] == symbol:
                if stock["tot_shares"] < shares:
                    flash("Not enough cash for shares")
                    return redirect("/")
                    
                else:
                    stock = stock["stock"]
                    current_price = lookup(stock)

                    if current_price is None:
                        flash("Symbol not found")
                        return redirect("/")
                        
                    price = current_price["price"]
                    total = shares * price
                    new_cash = current_user["cash"] - total
                    print(new_cash)

                    db.execute(
                        "UPDATE users SET cash = ? WHERE id = ?",
                        new_cash,
                        session["user_id"],
                    )

                    db.execute(
                        "INSERT INTO purchases (user, stock, shares, price) VALUES (?, ?, ?, ?);",
                        current_user["username"],
                        symbol,
                        shares,
                        price,
                    )

                return redirect("/")

    return render_template(
        "index.html",
        username=current_user["username"],
        balance=current_user["cash"],
        grand_total=grand_total,
        stocks=stock_info,
    )

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        user_buy = db.execute("SELECT * FROM users WHERE id = ?;", session["user_id"])
        stock = request.form.get("symbol").upper()
        shares = request.form.get("shares")

        if not stock:
            flash("Input valid stock ticker")
            return render_template("buy.html")

        getprice = lookup(stock)

        if getprice is None:
            flash("Input valid stock ticker")
            return render_template("buy.html")

        price = getprice["price"]

        if not shares or not shares.isdigit() or int(shares) <= 0:
            flash("Input a positive whole number of shares")
            return render_template("buy.html")

        user_cash = user_buy[0]  # only to use in 'cash' variable

        cash = int(user_cash["cash"]) - int(price) * int(shares)

        if user_cash["cash"] <= 0 or cash <= 0:
            
            flash("Not enough money in your account")
            return render_template("buy.html")

        db.execute(
            "INSERT INTO purchases (user, stock, shares, price) VALUES (?, ?, ?, ?);",
            user_cash["username"],
            stock,
            shares,
            price,
        )
        db.execute("UPDATE users SET cash = ? WHERE id = ?;", cash, session["user_id"])

        return redirect("/")
    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # query for username using current session user id
    usernames = db.execute("SELECT * FROM users WHERE id = ?;", session["user_id"])

    # convert id to username, then use username to query transactions
    username = usernames[0]
    transactions = db.execute(
        "SELECT stock, shares, date, price FROM purchases WHERE user = ? ORDER BY date DESC;",
        username["username"],
    )

    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Error handling
        # Ensure username was submitted
        if not request.form.get("username"):
            flash("Must provide a username")
            return render_template("login.html")

        # Ensure password was submitted
        elif not request.form.get("password"):
            flash("Must provide password")
            return render_template("login.html")

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            flash("Invalid username and/or password")
            return render_template("login.html")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        print(rows)
        print(session["user_id"])

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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    if request.method == "POST":
        symbol = request.form.get("symbol")
        stock = lookup(symbol)

        if not stock:
            flash("Enter a valid stock ticker")
            return render_template("quote.html")

        return render_template("quote.html", stock=stock)

    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    username = request.form.get("username")
    password = request.form.get("password")
    confirm = request.form.get("confirmation")

    if request.method == "POST":

        # Error handling
        # check for username
        if not username:
            flash("Input a username")
            return render_template("register.html")
            
        # check for password
        if not password:
            flash("Input a password")
            return render_template("register.html")
            
        # check for confirmation
        if not confirm:
            flash("Input password confirmation")
            return render_template("register.html")
            
        # check if passwords are matching
        elif confirm != password:
            flash("Passwords do not match")
            return render_template("register.html")
            
        # check username does not already exist
        rows = db.execute("SELECT * FROM users WHERE username = ?;", username)
        if len(rows) != 0:
            flash("Username already exists")
            return render_template("register.html")

        password = str(password)
        hash = generate_password_hash(password, method="pbkdf2", salt_length=16)
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?);", username, hash)
        return render_template("success.html")
    return render_template("register.html", name="register")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    current_user = db.execute(
        "SELECT username, cash FROM users WHERE id = ?;", session["user_id"]
    )
    current_user = current_user[0]

    stocks = db.execute(
        "SELECT SUM(shares) AS tot_shares, stock  FROM purchases WHERE user = ? GROUP BY(stock) HAVING tot_shares > 0;",
        current_user["username"],
    )

    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        
        # error handling
        if not symbol:
            flash("Select a stock")
            return render_template("sell.html")
            
        if not shares:
            flash("Input a positive share amount")
            return render_template("sell.html")
           
        shares = int(shares)

        if shares <= 0:
            flash("Input a positive share amount")
            return render_template("sell.html")

        for stock in stocks:
            if stock["stock"] == symbol:
                if stock["tot_shares"] < shares:
                    flash("Not enough shares")
                    return render_template("sell.html")
                else:
                    stock = stock["stock"]
                    current_price = lookup(stock)

                    if current_price is None:
                        flash("Symbol not found")
                        return render_template("sell.html")
                        
                    price = current_price["price"]
                    total = shares * price
                    new_cash = current_user["cash"] + total
                    print(new_cash)

                    db.execute(
                        "UPDATE users SET cash = ? WHERE id = ?",
                        new_cash,
                        session["user_id"],
                    )

                    db.execute(
                        "INSERT INTO purchases (user, stock, shares, price) VALUES (?, ?, ?, ?);",
                        current_user["username"],
                        symbol,
                        -shares,
                        price,
                    )

                return redirect("/")

    return render_template("sell.html", stocks=stocks)

# to run using python app.py
if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)