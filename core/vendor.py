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

    def __init__(self, url):
        """Initializes the MacVendorLookup class by loading the MAC vendor data.

        Args:
            url (str): The URL from which to fetch the MAC vendor data if the cache doesn't exist.
        """
        self.load_data(url)

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
        """Loads MAC vendor data from a local CSV file in the format:
        Registry, Assignment (OUI), Organization Name, Organization Address.

        Args:
            filename (str): The path to the CSV file to read from.

        Returns:
            list of dict: A list of dictionaries containing the fields:
                        'Registry', 'Assignment', 'Organization Name', and 'Organization Address'.
        """
        with open(filename, 'r', encoding='utf-8') as file:
            csvreader = csv.reader(file)
            mac_vendor_data = []
            next(csvreader)  # Skip header row
            for row in csvreader:
                if len(row) < 4:
                    continue

                mac_vendor_data.append({
                    'Registry': row[0],  # MA-L
                    'Assignment': row[1].replace("-", "").upper(),  # OUI (without dashes)
                    'Organization Name': row[2],  # Organization name
                    'Organization Address': row[3]  # Organization address
                })
            return mac_vendor_data


    @classmethod
    def _load_from_url(cls, url):
        """Loads MAC vendor data from a given URL in the same format as expected by the file.

        Args:
            url (str): The URL to fetch the MAC vendor data from.

        Returns:
            list of dict: A list of dictionaries containing the fields:
                        'Registry', 'Assignment', 'Organization Name', and 'Organization Address'.
        """
        response = requests.get(url, timeout=1)
        if response.status_code == 200:
            csv_data = StringIO(response.text)
            csvreader = csv.reader(csv_data)
            next(csvreader)  # Skip header row
            mac_vendor_data = []
            for row in csvreader:
                if len(row) < 4:
                    continue

                mac_vendor_data.append({
                    'Registry': row[0],  # MA-L
                    'Assignment': row[1].replace("-", "").upper(),  # OUI (without dashes)
                    'Organization Name': row[2],  # Organization name
                    'Organization Address': row[3]  # Organization address
                })
            return mac_vendor_data
        print(f"Failed to fetch data from {url}. Status code: {response.status_code}")
        return []



    @classmethod
    def _save_to_file(cls, filename, data):
        """Saves the MAC vendor data to a local CSV file.

        The file will contain four columns:
        Registry, Assignment (OUI), Organization Name, and Organization Address.

        Args:
            filename (str): The path to the file where the data should be saved.
            data (list of dict): A list of dictionaries containing the fields:
            'Registry', 'Assignment', 'Organization Name', and 'Organization Address'.
        """
        with open(filename, 'w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)

            # Write the header row
            writer.writerow(['Registry', 'Assignment', 'Organization Name', 'Organization Address'])

            # Write the data rows
            for entry in data:
                writer.writerow([
                    entry['Registry'],
                    entry['Assignment'],
                    entry['Organization Name'],
                    entry['Organization Address']
                ])


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
        if self.mac_vendor_data is not None:
            for entry in self.mac_vendor_data:
                if entry['Assignment'] == oui:
                    return entry['Organization Name']  # Return the organization name
        return "Vendor not found"
