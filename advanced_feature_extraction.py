import re
import socket
import math
from urllib.parse import urlparse

class FeatureExtraction:
    def __init__(self, url):
        self.url = url
        self.parsed = urlparse(url)
        self.hostname = self.parsed.netloc
        self.path = self.parsed.path

    # Basic Features
    def url_length(self):
        return len(self.url)

    def hostname_length(self):
        return len(self.hostname)

    def having_ip(self):
        try:
            socket.inet_aton(self.hostname)
            return 1
        except:
            return 0

    def dot_count(self):
        return self.url.count(".")

    def hyphen_count(self):
        return self.url.count("-")

    def digit_count(self):
        return sum(c.isdigit() for c in self.url)

    def digit_ratio(self):
        return self.digit_count() / len(self.url) if len(self.url) > 0 else 0

    def special_char_count(self):
        return len(re.findall(r"[@#$%^&*()+=\[\]{}|\\:;\"'<>,?/~`]", self.url))

    def special_char_ratio(self):
        return self.special_char_count() / len(self.url) if len(self.url) > 0 else 0

    def https(self):
        return 1 if self.parsed.scheme == "https" else 0

    def suspicious_words(self):
        suspicious = ['login', 'secure', 'update', 'verify', 'account', 'bank', 'free', 'bonus']
        return 1 if any(word in self.url.lower() for word in suspicious) else 0

    def suspicious_tld(self):
        suspicious = ['.tk', '.xyz', '.ru', '.cn', '.top', '.gq']
        return 1 if any(self.url.endswith(tld) for tld in suspicious) else 0

    def url_entropy(self):
        prob = [float(self.url.count(c)) / len(self.url) for c in dict.fromkeys(list(self.url))]
        return - sum([p * math.log2(p) for p in prob])

    # NEW STRONG FEATURES

    def subdomain_count(self):
        return self.hostname.count(".") - 1 if self.hostname.count(".") > 0 else 0

    def longest_token_length(self):
        tokens = re.split(r"[./\-?=&]", self.url)
        return max([len(token) for token in tokens]) if tokens else 0

    def consecutive_digit_count(self):
        matches = re.findall(r"\d+", self.url)
        return max([len(match) for match in matches]) if matches else 0

    def vowel_ratio(self):
        vowels = "aeiou"
        count = sum(c.lower() in vowels for c in self.url)
        return count / len(self.url) if len(self.url) > 0 else 0

    def double_slash_in_path(self):
        return 1 if "//" in self.path else 0

    def parameter_count(self):
        return self.url.count("?")

    def equal_sign_count(self):
        return self.url.count("=")

    def http_in_hostname(self):
        return 1 if "http" in self.hostname else 0

    def get_features(self):
        return [
            self.url_length(),
            self.hostname_length(),
            self.having_ip(),
            self.dot_count(),
            self.hyphen_count(),
            self.digit_count(),
            self.digit_ratio(),
            self.special_char_count(),
            self.special_char_ratio(),
            self.https(),
            self.suspicious_words(),
            self.suspicious_tld(),
            self.url_entropy(),
            self.subdomain_count(),
            self.longest_token_length(),
            self.consecutive_digit_count(),
            self.vowel_ratio(),
            self.double_slash_in_path(),
            self.parameter_count(),
            self.equal_sign_count(),
            self.http_in_hostname()
        ]