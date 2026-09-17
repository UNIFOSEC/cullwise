"""Intentionally insecure demo code for the ThreatLens dashboard scan. Not real."""

from flask import request


def hello():
    # Reflected XSS: untrusted input concatenated into HTML (CWE-79).
    return "<h1>Hi " + request.args["user"] + "</h1>"
