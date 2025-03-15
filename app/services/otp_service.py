import random

class OTPService:
    @staticmethod
    def generate_otp():
        """Generates a random 6-digit OTP"""
        return str(random.randint(100000, 999999))
