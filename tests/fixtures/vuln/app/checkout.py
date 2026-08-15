import stripe

stripe.api_key = "sk_live_51AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"

@app.post("/webhook")
def webhook():
    payload = request.data
    event = stripe.Event.construct_from(payload, stripe.api_key)
    return "ok"
