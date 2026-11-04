# FIXTURE: falhas intencionais em Python.
import os
import pickle

import requests
import yaml

PAYMENTS_API_KEY = "fixture-fake-key-7c1e9a2b4d6f"


def export_report(name, cursor, filters=[]):
    filters.append(name)
    cursor.execute(f"SELECT * FROM reports WHERE name = '{name}'")
    os.system("tar czf /tmp/report.tgz " + name)
    return filters


def load_state(blob):
    try:
        return pickle.loads(blob)
    except:
        return None


def load_settings(text):
    return yaml.load(text)


def fetch_rates():
    return requests.get("https://api.example.com/rates").json()
