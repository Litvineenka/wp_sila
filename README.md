<style>
    red {
        color: #a93434;
    }
</style>

# WP_Sila - WordPress Brute Force Tool

This tool attempts to brute force WordPress login credentials by trying multiple username and password combinations. It is intended for educational purposes only.

## Requirements

- Python 3.x
- `requests` library

## Installation

1. Clone the repository or download the script.
2. Install the required Python packages using pip:

```sh
pip install -r requirements.txt
```

## Usage

To use the tool, run the script with the target WordPress site URL and the password list file. You can also specify the number of concurrent threads.

### Example

```sh
python wp_sila.py http://example.com passwords.txt --threads 10
```

### Arguments

```sh
target: The URL of the target WordPress site.
```
```sh
password_list: The file containing the list of passwords to try.
```
```sh
--threads: (Optional) The number of concurrent threads to use (default is 10).
```

### Output

<b>wpbf-results.txt: A file containing the successful username and password combinations.</b>

## Script Details

- get_user_wpjson(session, target)

- Fetches usernames from the WordPress JSON API and saves them to a temporary file wpusername.tmp.
test_login(session, target, username, password)

- Attempts to log in to WordPress with the provided username and password. Successful attempts are recorded in wpbf-results.txt.
main()

- Handles user input, manages threading, and coordinates the brute force attempts.
License

## Important Notes ⚠️

<b><red>This tool should only be used on websites you own or have explicit permission to test.
Unauthorized use of this tool may violate terms of service and laws.</red></b>

<b><red>This tool is for educational purposes only. The author is not responsible for any misuse or damage caused by this tool.</red></b>

<i>This project is licensed under the MIT License. See the LICENSE file for details.</i>

