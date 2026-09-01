import yaml


def load_config(user_input):
    """
    Intentionally vulnerable test case.

    VAJRA should identify this yaml.load() call as unsafe
    deserialization. It uses yaml.Loader (not SafeLoader), which
    can execute arbitrary code embedded in the YAML document.
    """
    return yaml.load(user_input, Loader=yaml.Loader)


def main():
    user_input = input("Enter YAML: ")
    load_config(user_input)


if __name__ == "__main__":
    main()
