import smtplib

def send_email(email, msg):
    test_email = 'xxxxxxxx@gmail.com'
    password = 'xxxxx'
    with smtplib.SMTP("smtp.gmail.com") as connection:
        connection.starttls()
        connection.login(user=test_email, password=password)
        connection.sendmail(from_addr=test_email, to_addrs=email, msg=msg)
