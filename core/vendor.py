import os
import csv
from io import StringIO
import requests


class MacVendorLookup:
    mac_vendor_data = None

    @classmethod
    def load_data(cls, url):
        if cls.mac_vendor_data is None:
            cache_file = "oui.csv"
            if os.path.exists(cache_file):
                cls.mac_vendor_data = cls._load_from_file(cache_file)
            else:
                cls.mac_vendor_data = cls._load_from_url(url)
                cls._save_to_file(cache_file, cls.mac_vendor_data)

    @classmethod
    def _load_from_file(cls, filename):
        with open(filename, 'r') as file:
            csvreader = csv.reader(file)
            next(csvreader)  # Skip header
            mac_vendor_data = {}
            for row in csvreader:
                oui = row[1].replace("-", "").upper()[:6]
                vendor = row[2]
                mac_vendor_data[oui] = vendor
            return mac_vendor_data

    @classmethod
    def _load_from_url(cls, url):
        response = requests.get(url)
        if response.status_code == 200:
            csv_data = StringIO(response.text)
            csvreader = csv.reader(csv_data)
            next(csvreader)  # Skip header
            mac_vendor_data = {}
            for row in csvreader:
                oui = row[1].replace("-", "").upper()[:6]
                vendor = row[2]
                mac_vendor_data[oui] = vendor
            return mac_vendor_data
        else:
            print(f"Failed to fetch data from {url}. Status code: {response.status_code}")
            return {}

    @classmethod
    def _save_to_file(cls, filename, data):
        with open(filename, 'w') as file:
            writer = csv.writer(file)
            writer.writerow(["Organizationally Unique Identifier", "Organization Name"])
            for oui, vendor in data.items():
                writer.writerow([oui, vendor])

    def __init__(self, url):
        self.load_data(url)

    def lookup_vendor(self, mac_address):
        cleaned_mac = mac_address.upper().replace(":", "").replace("-", "")
        oui = cleaned_mac[:6]
        return self.mac_vendor_data.get(oui, "Vendor not found")