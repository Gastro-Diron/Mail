public function formatdata (string name, string email, string password) returns json{
    json data = {
                    "schemas": [],
                    "name": {
                        "givenName": name,
                        "familyName": ""
                    },
                    "userName": "DEFAULT/"+email,
                    "password": password,
                    "emails": [
                        {
                        "value": email,
                        "primary": true
                        }
                    ],
                    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                        "employeeNumber": "1234A",
                        "manager": {
                        "value": "Taylor"
                        },
                        "verifyEmail": true
                    },
                    "urn:scim:wso2:schema": {
                        "askPassword": false
                    }
                };
    return data;
}

public function checkDuplicate (string email) returns json {
    json data = {
                    "schemas": [
                        "urn:ietf:params:scim:api:messages:2.0:SearchRequest"
                    ],
                    "attributes": [
                        "userName"
                    ],
                    "filter": "userName co "+email
                };
    return data;
}