import requests
import hashlib
import sys


def request_api_data(query_data):
    url = "https://api.pwnedpasswords.com/range/" + query_data
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f"check the status code {res}")
    return res


def get_password_leak_counts(hashs, hash_to_check):
    hashs = (line.split(":") for line in hashs.text.splitlines())
    for h, count in hashs:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('UTF 8')).hexdigest().upper()
    first5_hash, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_hash)
    return get_password_leak_counts(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f"{password} was {count} times hacked, So please change password")
        else:
            print(f"{password} is secured, so keep it")
    return "done!"


if __name__ == '__main__':
    main(sys.argv[1:])