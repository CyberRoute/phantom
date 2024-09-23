"""
The MacVendorLookup load data about vendors from an oui.csv file
"""
import os
import csv
from io import StringIO
import requests


class MacVendorLookup:
    """Mac2Vendor class for translation of a MAC address to its vendor.

    This class looks up the vendor of a given MAC address using the
    Organizationally Unique Identifier (OUI) part of the MAC address.
    Data can be loaded either from a URL or a cached CSV file.

    Attributes:
        mac_vendor_data (dict): A dictionary mapping OUI prefixes to vendor names.
    """

    mac_vendor_data = None

    @classmethod
    def load_data(cls, url):
        """Loads MAC address to vendor data, either from a cached file or a URL.

        If the data is already loaded, this method does nothing.
        If a cache file (oui.csv) exists, the data is loaded from the file.
        Otherwise, the data is fetched from the provided URL and saved to the cache.

        Args:
            url (str): The URL from which to download the MAC vendor data.
        """
        if cls.mac_vendor_data is None:
            cache_file = "oui.csv"
            if os.path.exists(cache_file):
                cls.mac_vendor_data = cls._load_from_file(cache_file)
            else:
                cls.mac_vendor_data = cls._load_from_url(url)
                cls._save_to_file(cache_file, cls.mac_vendor_data)

    @classmethod
    def _load_from_file(cls, filename):
        """Loads MAC vendor data from a local CSV file.

        The CSV file should have a header row followed by rows of OUI and vendor information.

        Args:
            filename (str): The path to the CSV file to read from.

        Returns:
            dict: A dictionary mapping OUI (first 6 characters of MAC address) to vendor names.
        """
        with open(filename, 'r', encoding='utf-8') as file:
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
        """Loads MAC vendor data from a given URL.

        Fetches the CSV data from the provided URL and parses it into
        a dictionary of OUI to vendor mappings.

        Args:
            url (str): The URL to fetch the MAC vendor data from.

        Returns:
            dict: A dictionary mapping OUI (first 6 characters of MAC address) to vendor names.
            If the request fails, returns an empty dictionary.
        """
        response = requests.get(url, timeout=1)
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
        print(f"Failed to fetch data from {url}. Status code: {response.status_code}")
        return {}

    @classmethod
    def _save_to_file(cls, filename, data):
        """Saves the MAC vendor data to a local CSV file.

        The file will contain two columns: OUI and vendor name. This method
        will overwrite the file if it already exists.

        Args:
            filename (str): The path to the file where the data should be saved.
            data (dict): A dictionary containing OUI to vendor mappings.
        """
        with open(filename, 'w', encoding='utf-8') as file:
            writer = csv.writer(file)
            for oui, vendor in data.items():
                writer.writerow([oui, vendor])

    def __init__(self, url):
        """Initializes the MacVendorLookup class by loading the MAC vendor data.

        Args:
            url (str): The URL from which to fetch the MAC vendor data if the cache doesn't exist.
        """
        self.load_data(url)

    def lookup_vendor(self, mac_address):
        """Looks up the vendor for a given MAC address.

        The method extracts the first six characters (OUI) from the MAC address,
        which identifies the vendor. If the OUI is found in the loaded data, the
        corresponding vendor is returned; otherwise, it returns "Vendor not found".

        Args:
            mac_address (str): The MAC address to look up, in formats like
            XX:XX:XX:YY:YY:YY or XX-XX-XX-YY-YY-YY.

        Returns:
            str: The vendor name associated with the OUI, or "Vendor not found"
            if the OUI is not recognized.
        """
        cleaned_mac = mac_address.upper().replace(":", "").replace("-", "")
        oui = cleaned_mac[:6]
        return self.mac_vendor_data.get(oui, "Vendor not found")
