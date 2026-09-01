import subprocess

user_input = input("Command: ")
subprocess.call(user_input, shell=True)