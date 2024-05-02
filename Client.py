from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import Config
from smtplib import SMTP

if __name__ == '__main__':

    client = SMTP(Config.get_smtp_server(), Config.get_smtp_port())
    msg = MIMEMultipart()
    msg['From'] = 'tony'
    msg['To'] = 'tt'
    msg['Subject'] = 'Test'
    msg.attach(MIMEText('mail_message', 'html'))
    client.login('tony','123456')
    client.send_message(msg)
