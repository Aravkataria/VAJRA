def connect_to_database():
    """
    Intentionally vulnerable test case.

    VAJRA should identify this literal string assigned to a
    credential-shaped variable name as a hardcoded credential.
    """
    password = "hunter2-supersecret"
    return password
