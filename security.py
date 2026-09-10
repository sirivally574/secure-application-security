import re
from werkzeug.security import check_password_hash


def validate_username(username):
    """
    Username must contain only letters, numbers and underscores.
    Length: 3-20 characters.
    """

    if not username:
        return False, "Username is required."

    if len(username) < 3 or len(username) > 20:
        return False, "Username must be between 3 and 20 characters."

    if not re.fullmatch(r"[A-Za-z0-9_]+", username):
        return False, "Username can contain only letters, numbers and underscores."

    return True, ""


def validate_password(password):
    """
    Basic password security policy.
    """

    if not password:
        return False, "Password is required."

    if len(password) < 8:
        return False, "Password must contain at least 8 characters."

    if len(password) > 64:
        return False, "Password must not exceed 64 characters."

    if not re.search(r"[A-Z]", password):
        return False, "Password must contain an uppercase letter."

    if not re.search(r"[a-z]", password):
        return False, "Password must contain a lowercase letter."

    if not re.search(r"\d", password):
        return False, "Password must contain a number."

    if not re.search(r"[^A-Za-z0-9]", password):
        return False, "Password must contain a special character."

    return True, ""


def verify_password(password, password_hash):
    return check_password_hash(password_hash, password)


def get_password_strength(password):
    """
    Returns a simple password strength classification.
    """

    score = 0

    if len(password) >= 8:
        score += 1

    if len(password) >= 12:
        score += 1

    if re.search(r"[A-Z]", password):
        score += 1

    if re.search(r"[a-z]", password):
        score += 1

    if re.search(r"\d", password):
        score += 1

    if re.search(r"[^A-Za-z0-9]", password):
        score += 1

    if score <= 2:
        return "Weak"

    if score <= 4:
        return "Medium"

    return "Strong"