import ballerina/email;
import ballerina/io;

configurable string emailHost = io:readln("Input the host of your SMTP service: ");
configurable string userName = io:readln("Input the username of your SMTP Client (Sender email): ");
configurable string smtpPassword = io:readln("Input the password of your SMTP Client: ");

public function sendEmail(string toemail, string verificationCode) returns string|error {
    email:SmtpClient smtpClient = check new (emailHost, userName , smtpPassword);
    email:Message email = {
        to: [toemail],
        subject: "Verification Email",
        body: "Please enter this code in the application UI to verify your email address:" +
        "Your code is "+verificationCode+". This verification code will expire in 5 minutes.",
        'from: userName
    };
    check smtpClient->sendMessage(email);
    return verificationCode;
}

