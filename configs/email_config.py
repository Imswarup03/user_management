import smtplib
import os
from dotenv import load_dotenv
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import jsonify


load_dotenv()



class EmailSender:
    def __init__(self):
        self.email = os.environ.get('EMAIL') 
        self.password = os.environ.get("GMAIL_APP_PASSWORD")
        self.smtp_server = 'smtp.gmail.com'
        self.smtp_port = 587
        print ( "SMTP server Started")
        print('password', self.password)
        
    # @cached(cache={})
    def send_email(self, receiver_email, subject, body):
        try:
            msg = MIMEMultipart()
            msg['From'] = self.email
            print("message from", msg['From'])
            msg['To'] = receiver_email

            msg['Subject'] = subject

            msg.attach(MIMEText(body, 'plain'))

            with smtplib.SMTP(self.smtp_server, self.smtp_port) as smtp:
                smtp.starttls()
                smtp.login(self.email, self.password)
                smtp.send_message(msg)
            
            print("Email sent successfully!")
            return jsonify({'message': "email sent", 'statusCode':200}), 200
        except Exception as e:
            # print(f"Failed to send email: {e}")
            raise
