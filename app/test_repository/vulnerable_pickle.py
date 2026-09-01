import pickle


def load_session(user_input):
    """
    Intentionally vulnerable test case.

    VAJRA should identify this pickle.loads() call as unsafe
    deserialization. Unlike yaml.load(), there is no "safe loader"
    for pickle -- unpickling attacker-controlled bytes can always
    execute arbitrary code.
    """
    return pickle.loads(user_input)
