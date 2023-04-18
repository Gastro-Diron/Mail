import ballerina/random;

public function genCode () returns string|error {
    int randomInteger = check random:createIntInRange(100000, 999999);
    return randomInteger.toString();
}