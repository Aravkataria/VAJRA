import subprocess


def run_command(user_input):
    """
    Intentionally vulnerable test case.

    VAJRA should identify the use of shell=True with
    user-controlled input as a command-injection risk.
    """
    subprocess.call(user_input, shell=True)


def execute_code(user_input):
    """
    Intentionally vulnerable test case.

    VAJRA should identify the use of eval() with
    user-controlled input as an unsafe dynamic execution risk.
    """
    eval(user_input)


def main():
    user_input = input("Enter command: ")

    run_command(user_input)

    execute_code(user_input)


if __name__ == "__main__":
    main()