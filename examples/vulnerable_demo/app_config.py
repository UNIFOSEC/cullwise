"""Intentionally insecure demo code. The value below is a fake placeholder."""

# Hardcoded credential (CWE-798). This is NOT a real key — it is a demo string
# deliberately shaped to trip generic secret detection without matching any
# real provider's format (so it won't trigger push-protection secret scanning).
API_KEY = "demo1234567890abcdefFAKEsecretVALUExyz"
