# !!!------------------ ASSIGNMENTS -----------------------!!! #
# Various assignments that are used in script

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Edge/16.16299"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"
]

PROXY_STORAGE_FILE = 'proxy_data.json'
PROXY_BLACKLIST_FILE = 'proxy_blacklist.json'
IP_REPUTATION_CHECK_LIMIT = 1000
API_KEY = 'xxx'
TEST_URL = "https://httpbin.org/ip"
HTTPS_URL = "https://www.google.com"
DNS_LEAK_TEST_URL = "https://www.dnsleaktest.com/"
HEADERS_URL = "https://httpbin.org/headers"
ANYTHING_URL = "https://httpbin.org/anything"
COOKIE_TEST_URL = "https://httpbin.org/cookies"
SPEED_TEST_THRESHOLD = 100  # seconds

# !!!--------------- END OF ASSIGNMENTS -------------------!!! #

# !!!------------------ PACKAGE IMPORT --------------------!!! #
# This section is dedicated to importing necessary packages for the script to function correctly.

# ------------- CORE FUNCTIONALITY ------------- #
## ---------- SUBPROCESS ----------- ##
# Importing the subprocess module to allow the script to spawn new processes, connect to their input/output/error pipes, and obtain their return codes.
# [Docs of subprocess: https://docs.python.org/3/library/subprocess.html]
import subprocess
## -------------- SYS -------------- ##
# Importing the sys module to provide access to some variables used or maintained by the interpreter and to functions that interact strongly with the interpreter.
# [Docs of sys: https://docs.python.org/3/library/sys.html]
import sys

# Defining a dictionary to hold the package names and their respective modules to be imported.
# If a package has no specific modules to import, the value is None.
# If a package has a specific module to import, the value is the module name as a string.
# If a package has multiple specific modules to import, the value is a list of the module names.

packages = {
    ## -------------- OS --------------- ##
    # Importing the os module to provide a way of using operating system dependent functionality.
    # [Docs of os: https://docs.python.org/3/library/os.html]
    'os': None,

    # ----------------- CONCURRENCY ---------------- #
    ##------- CONCURRENT.FUTURES ------- ##
    # Importing the concurrent.futures module to provide a high-level interface for asynchronously executing callables.
    # [Docs of concurrent.futures: https://docs.python.org/3/library/concurrent.futures.html]
    'concurrent.futures': None,

    # ---------------- DATA PARSING ---------------- #
    ## -------------- BS4 -------------- ##
    # Importing the BeautifulSoup class from bs4 module to parse HTML and XML documents.
    # [Docs of bs4: https://www.crummy.com/software/BeautifulSoup/bs4/doc/]
    'bs4': 'BeautifulSoup',
    ## -------------- JSON ------------- ##
    # Importing the json module to work with JSON data.
    # [Docs of json: https://docs.python.org/3/library/json.html]
    'json': None,

    # ----------------- NETWORKING ----------------- #
    ## ------ FAKE_USERAGENT ----------- ##
    # Importing the UserAgent class from fake_useragent module to generate random user agent strings.
    # [Docs of fake_useragent: https://pypi.org/project/fake-useragent/]
    'fake_useragent': 'UserAgent',
    ## ------------- REQUESTS ---------- ##
    # Importing the requests module to send HTTP requests and handle HTTP responses effectively.
    # [Docs of requests: https://docs.python-requests.org/en/latest/]
    'requests': None,

    # ---------------- PROGRESS BAR ---------------- #
    ## -------------- TQDM ------------- ##
    # Importing the tqdm module to provide a fast, extensible progress bar.
    # [Docs of tqdm: https://tqdm.github.io/]
    'tqdm': 'tqdm',

    # ------------------- SECURITY ----------------- #
    ## ------------ HASHLIB ------------ ##
    # Importing the hashlib module to provide a variety of secure hash and message digest algorithms
    # [Docs of hashlib: https://docs.python.org/3/library/hashlib.html]
    'hashlib': None,

    # ------------- TIME AND RANDOMNESS ------------ #
    ## ------------ RANDOM ------------- ##
    # Importing the random module to generate random numbers and set random seed.
    # [Docs of random: https://docs.python.org/3/library/random.html]
    'random': None,  
    ## -------------- TIME ------------- ##
    # Importing the time module to provide various time-related functions.
    # [Docs of time: https://docs.python.org/3/library/time.html]
    'time': None,
    ## ----------- DATETIME ------------ ##
    # Importing the datetime module to work with dates and times.
    # [Docs of datetime: https://docs.python.org/3/library/datetime.html]
    'datetime': None
}


def install_and_import(packages):
    """
    This function attempts to import the specified packages and their respective modules.
    If a package is not installed, it will attempt to install it using pip, then import it.
    
    :param dict packages: A dictionary where keys are package names and values are either None, a module name, or a list of module names.
    """
    # Iterating through each package and its modules in the provided dictionary.
    for package, modules in packages.items():
        try:
            # Trying to import the package.
            exec(f"import {package}", globals())
            print(f"{package} is already imported.")
        except ImportError:
            # If the package is not installed, print a message, then attempt to install and import the package using pip.
            print(f"{package} not imported. Installing and importing now...")
            subprocess.run([sys.executable, '-m', 'pip', 'install', package], check=True)
            exec(f"import {package}", globals())
            print(f"{package} installed and imported successfully.")
        
        # If there are specific modules to import from the package.
        if modules:
            # If multiple modules are specified as a list, iterate through the list and import each module.
            if isinstance(modules, list):
                for module in modules:
                    exec(f"from {package} import {module}", globals())
                    print(f"Imported {module} from {package}.")
            else:
                # If a single module is specified, import that module.
                exec(f"from {package} import {modules}", globals())
                print(f"Imported {modules} from {package}.")

# !!!-------------- END OF PACKAGE IMPORT -----------------!!! #

# !!!------------------ HELPER FUNCTIONS  -----------------!!! #

def fetch_new_user_agents():
    max_duration = 10  
    start_time = time.time()
    new_user_agents = set()
    while (time.time() - start_time) < max_duration:
        ua = UserAgent(browsers=['chrome'], min_percentage=1.0, fallback='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36')
        new_agent = ua.random
        if new_agent not in USER_AGENTS and new_agent not in new_user_agents:
            new_user_agents.add(new_agent)
    return list(new_user_agents)

def load_json_file(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            content = file.read()
            if content:
                try:
                    return json.loads(content)
                except json.JSONDecodeError:
                    print(f'Warning: {file_path} contains invalid JSON. Returning an empty dictionary.')
            else:
                print(f'Warning: {file_path} is empty. Returning an empty dictionary.')
    else:
        print(f'Warning: {file_path} does not exist. Returning an empty dictionary.')
    return {}

def save_json_file(data, file_path):
    with open(file_path, 'w') as file:
        json.dump(data, file)


def is_fresh(proxy_data):
    last_tested = datetime.datetime.strptime(proxy_data['last_tested'], '%Y-%m-%d')
    return (datetime.datetime.now() - last_tested).days < 2 


##---------- IP REPUTATION --------- ##
class IPReputationChecker:
    """
    A class to encapsulate IP reputation checking functionality,
    allowing for more organized tracking of the number of checks made.
    """

    def __init__(self):
        self.ip_reputation_checks_made = 0

    def is_check_limit_reached(self):
        """
        Determines if the limit for IP reputation checks has been reached.
        
        Returns:
        - bool: True if the limit is reached, False otherwise.
        """
        return self.ip_reputation_checks_made >= IP_REPUTATION_CHECK_LIMIT

    def increment_check_counter(self):
        """Increments the counter tracking the number of IP reputation checks made."""
        self.ip_reputation_checks_made += 1

    def check_ip_reputation(self, proxy):
        """
        Checks the reputation of the provided IP address using the AbuseIPDB API.
        
        If the limit of IP reputation checks is reached, this function assumes the IP 
        is safe and returns True. Otherwise, it sends a request to the AbuseIPDB API
        to check the reputation of the provided IP, increments the check counter, and
        returns whether the IP is considered safe based on the abuse confidence score.
        
        Parameters:
        - proxy (str): The proxy IP address and port as a string in the format 'IP:port'.
        
        Returns:
        - bool: True if the IP is considered safe, False otherwise.
        """
        if self.is_check_limit_reached():
            return True  # Assuming you want to treat it as "safe" if the limit is reached
        ip_address = proxy.split(':')[0]
        ip_check_url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}"
        headers = {
            'Key': API_KEY,
            'Accept': 'application/json'
        }
        response = requests.get(ip_check_url, headers=headers)
        self.increment_check_counter()  # Increment the counter after each check
        if response.status_code == 200 and response.json().get('abuseConfidenceScore', 0) < 50:
            return True
        return False
    
    def check_multiple_ip_reputations(self, proxies):
        """
        Checks the reputation of multiple IP addresses using the AbuseIPDB API.
        
        Parameters:
        - proxies (list): A list of proxy IP addresses and ports as strings in the format 'IP:port'.
        
        Returns:
        - dict: A dictionary where keys are the IP addresses and values are booleans indicating 
                whether the IP is considered safe (True) or not (False).
        """
        reputation_results = {}  # Initialize an empty dictionary to collect the results
        for proxy in proxies:  # Iterate through each proxy in the provided list
            is_safe = self.check_ip_reputation(proxy)  # Check the reputation of the current IP
            reputation_results[proxy] = is_safe  # Store the result in the dictionary
        return reputation_results  # Return the dictionary of reputation results
    

def check_cert_transparency(proxy):
    """
    Checks the Certificate Transparency logs for a given IP address using the crt.sh service.
    
    This function constructs a URL for querying the crt.sh service with the IP address extracted
    from the provided proxy string. It sends a GET request to this URL, and checks the response
    to determine if there are any Certificate Transparency logs for the IP address.
    
    Parameters:
    - proxy (str): The proxy string in the format 'IP:port'.
    
    Returns:
    - bool: True if there are Certificate Transparency logs for the IP, False otherwise or if an error occurs.
    """
    ip_address = proxy.split(':')[0] # Extract the IP address from the proxy string
    ct_check_url = f"https://crt.sh/?q={ip_address}&output=json"  # Construct the URL for the crt.sh query
    response = send_request(ct_check_url)  # Send the GET request
    if response and response.json():
        return True  # Return True if the response contains data (i.e., there are CT logs for the IP)
    return False  # Return False if the response is None, or if it doesn't contain data

class ProxyTester:
    def __init__(self, proxy, headers=None):
        self.proxy = proxy
        self.headers = headers
        self.proxy_dict = {
            "http": f"http://{proxy}",
            "https": f"http://{proxy}",
        }

    # Speed Test
    def test_speed(self):
        start_time = time.time()
        try:
            response = requests.get(TEST_URL, proxies=self.proxy_dict, headers=self.headers, timeout=120)
        except requests.RequestException as e:
            return False, str(e)
        elapsed_time = time.time() - start_time
        if elapsed_time > SPEED_TEST_THRESHOLD:
            return False, f"Slow Proxy (Speed Test failed)"
        return True, "Speed Test Passed"

    # Test basic connectivity and IP masking
    def test_ip_masking(self):
        try:
            response = requests.get(TEST_URL, proxies=self.proxy_dict, headers=self.headers)
            if response.status_code == 200:
                original_ip = requests.get(TEST_URL).json()["origin"]
                proxy_ip = response.json()["origin"]
                if original_ip == proxy_ip:
                    return False, f"!!!------ Transparent Proxy (IP Masking Test failed) ------!!!"
        except requests.RequestException as e:
            return False, str(e)
        return True, "IP Masking Test Passed"

    # Anonymity Test
    def test_anonymity_level(self):
        try:
            response = requests.get(ANYTHING_URL, proxies=self.proxy_dict, headers=self.headers, timeout=120)
            if response.status_code == 200:
                request_info = response.json()
                origin_ip = request_info.get('origin', '')
                forwarded_for = request_info.get('headers', {}).get('X-Forwarded-For', '')
                if origin_ip or forwarded_for:
                    return False, f"!!!------ Proxy Anonymity Level Check failed ------!!!"
        except requests.RequestException as e:
            return False, str(e)
        return True, "Anonymity Level Test Passed"
    
    # Test HTTPS support
    def test_https_support(self):
        try:
            response = requests.get(HTTPS_URL, proxies=self.proxy_dict, headers=self.headers, timeout=120)
            if response.status_code != 200:
                return False, f"!!!------ No HTTPS Support (HTTPS Test failed) ------!!!"
        except requests.RequestException as e:
            return False, str(e)
        return True, "HTTPS Support Test Passed"

    # Test for data tampering
    def test_data_tampering(self):
        try:
            direct_content = requests.get(HTTPS_URL).content
            proxy_content = requests.get(HTTPS_URL, proxies=self.proxy_dict, headers=self.headers).content
            if len(direct_content) != len(proxy_content):
                return False, f"!!!------ Potential Data Tampering (Data Tampering Test failed -- Length) ------!!!"
            direct_hash = hashlib.md5(direct_content).hexdigest()
            proxy_hash = hashlib.md5(proxy_content).hexdigest()
            if direct_hash != proxy_hash:
                return False, f"!!!------ Potential Data Tampering (Data Tampering Test failed -- Hash) ------!!!"
        except requests.RequestException as e:
            return False, str(e)
        return True, "Data Tampering Test Passed"

    # Check for Script Injection
    def test_script_injection(self):
        try:
            direct_content = requests.get(HTTPS_URL).content
            proxy_content = requests.get(HTTPS_URL, proxies=self.proxy_dict, headers=self.headers).content
            direct_soup = BeautifulSoup(direct_content, 'html.parser')
            proxy_soup = BeautifulSoup(proxy_content, 'html.parser')
            if len(direct_soup.find_all('script')) != len(proxy_soup.find_all('script')):
                return False, f"!!!------ Script Injection Detected (Script Injection Test failed) ------!!!"
        except requests.RequestException as e:
            return False, str(e)
        return True, "Script Injection Test Passed"   
    
    # Test DNS Leak
    def test_dns_leak(self):
        try:
            dns_response = requests.get(DNS_LEAK_TEST_URL, proxies=self.proxy_dict, headers=self.headers, timeout=120)
            if "Your IP" in dns_response.text:
                return False, f"!!!------ Potential DNS Leak (DNS Leak Test failed) ------!!!"
        except requests.RequestException as e:
            return False, str(e)
        return True, "DNS Leak Test Passed"
    
    # Header Preservation Test
    def test_header_preservation(self):
        try:
            direct_headers = requests.get(HEADERS_URL).json()["headers"]
            proxy_headers = requests.get(HEADERS_URL, proxies=self.proxy_dict, headers=self.headers).json()["headers"]
            if direct_headers != proxy_headers:
                return False, f"!!!------ Headers Modified (Header Test failed) ------!!!"
        except requests.RequestException as e:
            return False, str(e)
        return True, "Header Preservation Test Passed"

    # Check for Cookie Handling:
    def test_cookie_handling(self):
        try:
            cookies = dict(test_cookie="test_value")
            response = requests.get(COOKIE_TEST_URL, proxies=self.proxy_dict, headers=self.headers, cookies=cookies)
            if 'test_cookie' not in response.json().get('cookies', {}):
                return False, f"!!!------ Cookie Handling Issue Detected (Cookie Test failed) ------!!!"
        except requests.RequestException as e:
            return False, str(e)
        return True, "Cookie Handling Test Passed"
    
    # Certificate Transparency Logs Check:
    def test_cert_transparency(self):
        if not check_cert_transparency(self.proxy):
            return False, f"!!!------ Certificate not in transparency logs (Certificate Transparency Test failed) ------!!!"
        return True, "Certificate Transparency Test Passed"

    # Check for Malicious IP Addresses
    def test_ip_reputation(self):
        ip_checker = IPReputationChecker()  # Create an instance of IPReputationChecker
        is_safe = ip_checker.check_ip_reputation(self.proxy)  # Call the check_ip_reputation method
        if not is_safe:
            return False, f"!!!------ IP has a bad reputation (Malicious IP Test failed) ------!!!"
        return True, "Malicious IP Test Passed"
    
    def test_proxy(self, custom_url=None):
        # List of test methods to run
        tests = [
            self.test_speed,
            self.test_ip_masking,
            self.test_anonymity_level,
            self.test_https_support,
            self.test_data_tampering,
            self.test_script_injection,
            self.test_dns_leak,
            self.test_header_preservation,
            self.test_cookie_handling,
            self.test_cert_transparency,
            self.test_ip_reputation,
        ]

        # Execute each test
        for test in tests:
            passed, message = test()
            if not passed:
                return False, message

        # Custom URL Test (non-critical)
        if custom_url:
            try:
                custom_response = requests.get(custom_url, proxies=self.proxy_dict, headers=self.headers, timeout=120)
                if custom_response.status_code != 200:
                    print(f"Warning: Cannot access {custom_url} (Custom URL Test failed)")
            except requests.RequestException as e:
                print(f"Warning: Error occurred while accessing {custom_url}: {str(e)}")
        
        return True, "Safe and Usable"
    
    def test_user_agents(self):
            successful_user_agents = []
            for user_agent in USER_AGENTS:
                self.headers = {"User-Agent": user_agent}
                is_safe, message = self.test_proxy()
                if is_safe:
                    successful_user_agents.append(user_agent)
            if successful_user_agents:
                return successful_user_agents, None  # Return None if there's no error
            else:
                return None, "All user agents failed"

def test_proxy_general(proxy, test_all_user_agents=False, concurrency=False):
    tester = ProxyTester(proxy)
    if test_all_user_agents:
        successful_user_agents, error_message = tester.test_user_agents()
        if successful_user_agents:
            return proxy, successful_user_agents, None  # Return None if there's no error
        else:
            return proxy, None, error_message
    else:
        is_safe, message = tester.test_proxy()
        if is_safe:
            return proxy, None, None  # Return None for user agents and error message
        else:
            return proxy, None, message

def test_all_proxies(proxies, test_all_user_agents=False, concurrency=False):
    successful_proxy_headers = []  # List to store successful proxy/header combinations
    error_messages = []  # List to store error messages

    def handle_result(result):
        proxy, user_agents, error_message = result
        if user_agents or not test_all_user_agents:
            successful_proxy_headers.append((proxy, user_agents))
        if error_message:
            error_messages.append((proxy, error_message))

    if concurrency:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(test_proxy_general, proxy, test_all_user_agents, concurrency) for proxy in proxies]
            for future in tqdm(concurrent.futures.as_completed(futures), total=len(proxies)):
                handle_result(future.result())
    else:
        for proxy in tqdm(proxies):
            result = test_proxy_general(proxy, test_all_user_agents)
            handle_result(result)

    return successful_proxy_headers, error_messages


# !!!------------- END OF HELPER FUNCTIONS ----------------!!! #

# !!!---------------------- SETUP  ------------------------!!! #

def main(test_all_user_agents=False, concurrency=False):
    global USER_AGENTS
    
    # Load data
    stored_proxies = load_json_file(PROXY_STORAGE_FILE)
    blacklist = set(load_json_file(PROXY_BLACKLIST_FILE))
    all_proxies = set()

    # Update user agents
    new_user_agents = fetch_new_user_agents()
    USER_AGENTS.extend(new_user_agents)
    USER_AGENTS = list(set(USER_AGENTS))

    # Fetch proxies
    # However you get your proxies 

    # Filter proxies
    proxies_to_test = [proxy for proxy in all_proxies if proxy not in blacklist and (proxy not in stored_proxies or not is_fresh(stored_proxies[proxy]))]

    # Test proxies
    successful_proxy_headers, error_messages  = test_all_proxies(proxies_to_test, test_all_user_agents, concurrency)
    
    # Print error messages
    for proxy, error_message in error_messages:
        print(f"Proxy: {proxy}, Error: {error_message}")

    # Process the successful proxies and store data
    successful_proxies = {item[0]: item[1] for item in successful_proxy_headers}
    
    for proxy in proxies_to_test:
        if proxy in successful_proxies:
            stored_proxies[proxy] = {
                'user_agents': successful_proxies[proxy],
                'last_tested': datetime.datetime.now().strftime('%Y-%m-%d'),
                'failure_count': 0  # Reset failure count on success
            }
        else:
            # Increment failure count on failure, or initialize to 1 if not previously stored
            failure_count = stored_proxies.get(proxy, {}).get('failure_count', 0) + 1
            stored_proxies[proxy] = {
                'user_agents': [],
                'last_tested': datetime.datetime.now().strftime('%Y-%m-%d'),
                'failure_count': failure_count
            }
            # Blacklist proxies that have failed multiple times
            if failure_count >= 30:
                blacklist.add(proxy)

    # Save updated data
    save_json_file(stored_proxies, PROXY_STORAGE_FILE)
    save_json_file(list(blacklist), PROXY_BLACKLIST_FILE)
    
    return successful_proxy_headers

# Install required packages
install_and_import(packages)
# Run the main function
result = main(test_all_user_agents=False, concurrency=True)


# !!!------------------- END OF SETUP ---------------------!!! #
