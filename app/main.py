# app/main.py

"""
VAJRA Server Entrypoint.
Usage:
    python -m app.main
"""

import uvicorn


def main():
    uvicorn.run("app.api:app", host="127.0.0.1", port=8000, reload=True)


if __name__ == "__main__":
    main()