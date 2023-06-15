REST API document

1. Create an account
    1. General Scenario
        1. Enter your E-mail address and password.
        2. Press the 'Sign up' button...
            1. First, send E-mail, password and other information to the server, and the server sends the Session ID to the app. 
               (password need to be double-checked)
            3. To check if the e-mail is yours, send a mail (or sms?) containing the passcode (6 digits random number).
            4. Enter the Passcode in the App and send it to the server along with the Session ID
            5. Server transmits OTP hash value for OTP registration
            6. Show the QR code in the App or display the hash value so that you can directly enter it in the App
            7. If you click the Done button in the App, you will be directed to the OTP input window to check if the OTP is successful.
            8. Enter a 6-digit number in the OTP input window and send it to the server along with the Session ID
            9. If the OTP is correct, registration is successful!
    1. Exception scenario
        1. There is a password confirmation field, so if the two are different, an error occurs
        2. Reject the previously registered e-mail
        3. If the passcode is incorrect, the session information registered in the server is deleted.
        4. ...
        5. ...
1. Manage Accounts
    1. Change password
    1. Change your email
    1. When the password is incorrect more than 3 times
    1. When you forgot your password
1. Login
    1. General Scenario
        1. Enter ID/Password/OTP number.
        2. If correct, Server issues SessionID
        3. Future REST APIs need to request with SessionID
        4. Client send IP address/Public Key to server.
        5. server add client to live list.
    2. Exception scenario
2. Log out
    1. When client request log out, server deletes client's session id and remove the client from live list
4. Get contact list
    1. Server collects connected client list and send info to clients.
    2. Clients request contact list periodically.
    3. Contact information consists of basic client information, IP, and Public Key.
