import ballerina/http;
import flow1.email;
import flow1.codegen;
import flow1.formatData;
import ballerinax/mysql;
import ballerinax/mysql.driver as _;
import ballerina/sql;
import ballerina/time;
import ballerina/io;


configurable string orgname = io:readln("Input your organization name: ");
configurable string clientID = io:readln("Input the ClientID of the Asgardeo application: ");
configurable string clientSecret = io:readln("Input the ClientSecret of the Asgardeo application: ");
configurable string dbHost = io:readln("Input the host of your Database: ");
configurable string dbUser = io:readln("Input the user of your Database: ");
configurable string dbPassword = io:readln("Input the password of your Database: ");
configurable string dbName = io:readln("Input the name of your Database: ");
configurable string dbPortStr = io:readln("Input the port your Database :");


int dbPort = check int:fromString(dbPortStr);

string createScope = "internal_user_mgt_create";
string listScope = "internal_user_mgt_list";

http:Client Register = check new ("https://api.asgardeo.io/t/"+orgname+"/scim2", httpVersion = http:HTTP_1_1);

mysql:Client dbClient = check new (dbHost, dbUser, dbPassword, dbName, dbPort);

service on new http:Listener (9090){
    
    resource function post users (@http:Payload UserEntry userEntry) returns response|error|ConflictingEmailsError {
        string toemail = userEntry.email;
        FullUser|error gotUser = getUser(userEntry.email);
        response result;

        if gotUser is FullUser{
            return {
                body: {
                    errmsg: string:'join(" ", "Conflicting emails:"+userEntry.email)
                }
            }; 

        }else {
            json token = check makeRequest(orgname, clientID, clientSecret, listScope);
    
            json Msg = formatData:checkDuplicate(userEntry.email);
            json token_type_any = check token.token_type;
            json access_token_any = check token.access_token;
            string token_type = token_type_any.toString();  
            string access_token = access_token_any.toString();
            http:Response postData = check Register->post(path = "/Users/.search", message = Msg, headers = {"Authorization": token_type+" "+access_token, "Content-Type": "application/scim+json"});
            json num = check postData.getJsonPayload();
            int existingEntries = check num.totalResults;
            if existingEntries == 0 {
                string verificationCode = check codegen:genCode();
                string mailer  = check email:sendEmail(toemail,verificationCode);
                time:Utc verificationSentTime = time:utcNow();
                error? data = createUser(userEntry.email, userEntry.name, userEntry.country, mailer, "DEFAULT PASSWORD", verificationSentTime[0], 0);
                result = {status: "success", message: "User has been added to the Temporary UserStore"};
            } else {
                result = {status: "failure", message: "Already a user exists with the same email"};
            }
            return result;
        }
    }

    resource function get users/[string email] () returns response|error {
        FullUser|error gotUser = getUser(email);
        response result;

        if gotUser is FullUser{
            string verificationCode = check codegen:genCode();
            string mailer  = check email:sendEmail(gotUser.email,verificationCode);
            error? userDeletion = deleteUser(gotUser.email);
            time:Utc verificationSentTime = time:utcNow();
            error? data = createUser(gotUser.email, gotUser.name, gotUser.country, mailer, "DEFAULT PASSWORD", verificationSentTime[0], 0); 
            result = {status: "success", message: "New verification Code has been sent to your email"};
        } else {
            result = {status: "failure", message: "The email does not exist"};
        }
        return result;
    }

    resource function post users/[string email] (string password, string passKey) returns response|InvalidEmailError|error{
        FullUser|error gotUser = getUser(email);
        response result;
            if gotUser is FullUser {
                if passKey == gotUser.code{
                    error? userUpdation = updateUser(email, password);

                    json Msg = formatData:formatdata(gotUser.name,gotUser.email,password);
                    json token = check makeRequest(orgname,clientID,clientSecret,createScope);
                    json token_type_any = check token.token_type;
                    json access_token_any = check token.access_token;
                    string token_type = token_type_any.toString();  
                    string access_token = access_token_any.toString();
                    http:Response|http:ClientError postData = check Register->post(path = "/Users", message = Msg, headers = {"Authorization": token_type+" "+access_token, "Content-Type": "application/scim+json"});
                    if postData is http:Response {
                        int num = postData.statusCode;
                        if num == 201 {
                            error? userDeletion = deleteUser(email);
                        }
                        result = {status: "success", message: "The user is created successfully"};
                    } else {
                        result = {status: "failure", message: "Error in creating the User"};
                    }
                } else {
                    result = {status: "failure", message: "Incorrect passKey"};
                }
                return result;
            } else {
                return {
                    body: {
                        errmsg: string `Invalid Email: ${email}`
                    }
                };
            }
    }

    resource function delete users/[string email] () returns response|InvalidEmailError {
        FullUser|error gotUser = getUser(email);
        response result;

        if gotUser is FullUser {
            error? userDeletion = deleteUser(email);
            result = {status: "success", message: "User has been deleted successfully"};
            return result;
        } else {
            return {
                body: {
                    errmsg: string `Invalid Email: ${email}`
                }
            };
        }
    }
    
    resource function post verify (@http:Payload VerifyEntry verifyEntry) returns response {
        FullUser|error gotUser = getUser(verifyEntry.email);
        response result;
        
        if gotUser is FullUser {
            time:Utc verificationReceivedTime = time:utcNow();
            error? receivedTimeUpdation = updateReceivedTime(gotUser.email, verificationReceivedTime[0]);
            
            string verificationCode = gotUser.code;
            int verificationSentTime = gotUser.sentTime;

            int timeDifference = verificationReceivedTime[0] - verificationSentTime;

            if timeDifference < 300 {
                if verifyEntry.code == verificationCode {
                    result = {status: "success", message: "The code is correct"};
                } else {
                    result = {status: "failure", message: "The code is incorrect"};
                }
                
            } else {
                result = {status: "failure", message: "The verification Code has expired"};
            }
        } else{
            result = {status: "failure", message: "The Email does not exist"};
        }
        return result;
    }
}

public type UserEntry record {|
    readonly string email;
    string name;
    string country;
|};

public type FullUser record {|
    *UserEntry;
    string code;
    string password;
    int sentTime;
    int receivedTime;
|};

public type ConflictingEmailsError record {|
    *http:Conflict;
    ErrorMsg body;
|};

public type ErrorMsg record {|
    string errmsg;
|};

public type InvalidEmailError record {|
    *http:NotFound;
    ErrorMsg body;
|};

public type VerifyEntry record {|
    readonly string email;
    string code;
|};

public type response record {|
    string message;
    string status;
|};

function createUser(string email, string name, string country, string code, string password, int sentTime, int receivedTime) returns error?{
    sql:ParameterizedQuery query = `INSERT INTO TemporaryUserStore(email, name, country, code, password, sentTime, receivedTime)
                                  VALUES (${email}, ${name}, ${country}, ${code}, ${password}, ${sentTime}, ${receivedTime})`;
    sql:ExecutionResult result = check dbClient->execute(query);
}

function getUser(string email) returns FullUser|error{
    sql:ParameterizedQuery query = `SELECT * FROM TemporaryUserStore
                                    WHERE email = ${email}`;
    FullUser resultRow = check dbClient->queryRow(query);
    return resultRow;
}

function deleteUser(string email) returns error?{
    sql:ParameterizedQuery query = `DELETE from TemporaryUserStore WHERE email = ${email}`;
    sql:ExecutionResult result = check dbClient->execute(query);
}

function updateUser(string email, string password) returns error?{
    sql:ParameterizedQuery query = `UPDATE TemporaryUserStore SET password = ${password} WHERE email = ${email}`;
    sql:ExecutionResult result = check dbClient->execute(query);
}

function updateReceivedTime(string email, int receivedTime) returns error?{
    sql:ParameterizedQuery query = `UPDATE TemporaryUserStore SET receivedTime = ${receivedTime} WHERE email = ${email}`;
    sql:ExecutionResult result = check dbClient->execute(query);
}

public function makeRequest(string orgName, string clientId, string clientSecret, string scope) returns json|error|error {
    http:Client clientEP = check new ("https://api.asgardeo.io",
        auth = {
            username: clientId,
            password: clientSecret
        },
         httpVersion = http:HTTP_1_1
    );
    http:Request req = new;
    req.setPayload("grant_type=client_credentials&scope="+scope, "application/x-www-form-urlencoded");
    http:Response response = check clientEP->/t/[orgName]/oauth2/token.post(req);
    json tokenInfo = check response.getJsonPayload();
    return tokenInfo;
}