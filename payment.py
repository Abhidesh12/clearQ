import razorpay
import os
from dotenv import load_dotenv
from fastapi import HTTPException

load_dotenv()

RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET")

client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

def create_order(amount: float, currency: str = "INR", receipt: str = None):
    """
    Create a Razorpay order
    Amount in smallest currency unit (paise for INR)
    """
    try:
        order_amount = int(amount * 100)  # Convert to paise
        order_data = {
            "amount": order_amount,
            "currency": currency,
            "payment_capture": 1
        }
        if receipt:
            order_data["receipt"] = receipt
            
        order = client.order.create(data=order_data)
        return order
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Payment order creation failed: {str(e)}")

def verify_payment_signature(order_id: str, payment_id: str, signature: str):
    """
    Verify Razorpay payment signature
    """
    try:
        params_dict = {
            'razorpay_order_id': order_id,
            'razorpay_payment_id': payment_id,
            'razorpay_signature': signature
        }
        client.utility.verify_payment_signature(params_dict)
        return True
    except razorpay.errors.SignatureVerificationError:
        return False
    except Exception as e:
        return False

def get_payment_details(payment_id: str):
    """
    Fetch payment details from Razorpay
    """
    try:
        payment = client.payment.fetch(payment_id)
        return payment
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch payment details: {str(e)}")

def refund_payment(payment_id: str, amount: float):
    """
    Initiate refund
    """
    try:
        refund_amount = int(amount * 100)
        refund_data = {
            "payment_id": payment_id,
            "amount": refund_amount
        }
        refund = client.payment.refund(**refund_data)
        return refund
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Refund failed: {str(e)}")
