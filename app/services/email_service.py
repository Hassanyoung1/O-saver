import smtplib
import os
from email.mime.text import MIMEText
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class EmailService:
    @staticmethod
    def send_otp_email(email: str, otp: str):
        sender_email = os.getenv("EMAIL_USERNAME", "mailhog@example.com")
        sender_password = os.getenv("EMAIL_PASSWORD", "mailhog")  # Dummy password
        smtp_host = os.getenv("EMAIL_HOST", "localhost")
        smtp_port = int(os.getenv("EMAIL_PORT", 1025))  # MailHog's SMTP port

        subject = "Your O-Saver OTP Code"
        body = f"Your OTP code is {otp}. It expires in 5 minutes."

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = sender_email
        msg["To"] = email

        try:
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.sendmail(sender_email, email, msg.as_string())

            print(f"✅ OTP Sent Successfully (Captured by MailHog) → OTP: {otp}")
            return True
        except Exception as e:
            print("❌ Error sending email:", e)
            return False
