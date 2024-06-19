import smtplib
import os
from dotenv import load_dotenv
import asyncio

load_dotenv()
def send_email(receiver_email, subject,body):
    try:
        email = os.environ.get('EMAIL')
        password = os.environ.get('GMAIL_APP_PASSWORD')
        with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
            smtp.ehlo()  #identifies the server that we are using 
            # encrypt our traffic
            smtp.starttls()
            smtp.ehlo()

            smtp.login(email, password)

            subject = subject
            body = body

            msg = f'Subject: {subject}\n\n {body}'

            receiever_email = receiver_email
            smtp.sendmail(email, receiever_email, msg)
            return True
    except Exception as e:
        print("Error Occured while sending email", e)
        return False