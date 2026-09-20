#include "password_analyzer.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <string>
#include <unordered_set>

namespace pwa {
namespace {

// Widely published lists of the most common passwords. Attackers try these first, so
// being on the list matters far more than any character-class arithmetic.
const std::unordered_set<std::string> &common_passwords() {
    static const std::unordered_set<std::string> kList = {
        "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111",
        "1234567", "dragon", "123123", "baseball", "abc123", "football", "monkey", "letmein",
        "696969", "shadow", "master", "666666", "qwertyuiop", "123321", "mustang", "1234567890",
        "michael", "654321", "superman", "1qaz2wsx", "7777777", "121212", "000000", "qazwsx",
        "123qwe", "killer", "trustno1", "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter",
        "buster", "soccer", "harley", "batman", "andrew", "tigger", "sunshine", "iloveyou",
        "2000", "charlie", "robert", "thomas", "hockey", "ranger", "daniel", "starwars",
        "112233", "george", "computer", "michelle", "jessica", "pepper", "1111", "zxcvbn",
        "555555", "11111111", "131313", "freedom", "777777", "pass", "maggie", "159753",
        "aaaaaa", "ginger", "princess", "joshua", "cheese", "amanda", "summer", "love",
        "ashley", "nicole", "chelsea", "biteme", "matthew", "access", "yankees", "987654321",
        "dallas", "austin", "thunder", "taylor", "matrix", "admin", "welcome", "login",
        "changeme", "secret", "guest", "root", "test", "user", "default", "passw0rd",
        "qwerty123", "letmein1", "password1", "abcdef", "abcd1234", "1q2w3e4r", "iloveyou1",
        "monkey1", "dragon1", "master1", "sunshine1", "princess1", "football1", "baseball1",
        "whatever", "hello", "hello123", "charlie1", "donald", "qwer1234", "google", "lovely",
    };
    return kList;
}

// Undo the substitutions people use to disguise a dictionary word.
char unleet(char c) {
    switch (c) {
        case '@': case '4': return 'a';
        case '0': return 'o';
        case '1': case '!': case '|': return 'i';
        case '3': return 'e';
        case '5': case '$': return 's';
        case '7': case '+': return 't';
        default: return c;
    }
}

std::string lower(std::string s) {
    for (char &c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool in_list(const std::string &s) { return common_passwords().count(s) > 0; }

// Ordered strings whose neighbours count as a "run" when typed in sequence, either direction.
const std::array<const char *, 5> kOrders = {
    "abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop", "asdfghjkl", "zxcvbnm"};

int position_in(const char *order, char c) {
    for (int i = 0; order[i]; ++i) {
        if (order[i] == c) return i;
    }
    return -1;
}

// Marks characters an attacker would not need to search for: everything after the first of a
// repeated block or an ascending/descending run of three or more. Returns (repeat, run) maxima.
struct Patterns {
    std::vector<bool> free;
    int longest_repeat = 0;
    int longest_run = 0;
};

Patterns find_patterns(const std::string &s) {
    Patterns p;
    p.free.assign(s.size(), false);
    if (s.empty()) return p;

    size_t i = 0;
    while (i < s.size()) {
        size_t j = i;
        while (j + 1 < s.size() && s[j + 1] == s[i]) ++j;
        int block = static_cast<int>(j - i + 1);
        p.longest_repeat = std::max(p.longest_repeat, block);
        if (block >= 3) {
            for (size_t k = i + 1; k <= j; ++k) p.free[k] = true;
        }
        i = j + 1;
    }

    const std::string low = lower(s);
    p.longest_run = 1;
    for (const char *order : kOrders) {
        for (int dir : {1, -1}) {
            size_t a = 0;
            while (a < low.size()) {
                size_t b = a;
                while (b + 1 < low.size()) {
                    int x = position_in(order, low[b]);
                    int y = position_in(order, low[b + 1]);
                    if (x < 0 || y < 0 || y != x + dir) break;
                    ++b;
                }
                int run = static_cast<int>(b - a + 1);
                if (run >= 3) {
                    p.longest_run = std::max(p.longest_run, run);
                    for (size_t k = a + 1; k <= b; ++k) p.free[k] = true;
                }
                a = (b == a) ? a + 1 : b;
            }
        }
    }
    return p;
}

}  // namespace

bool is_common(const std::string &password) {
    std::string s = lower(password);
    if (s.empty()) return false;
    if (in_list(s)) return true;

    std::string plain;
    plain.reserve(s.size());
    for (char c : s) plain.push_back(unleet(c));
    if (in_list(plain)) return true;

    // Word plus a short decoration: "password2024", "letmein!!", "dragon99".
    for (const std::string &candidate : {s, plain}) {
        std::string stem = candidate;
        for (int strip = 0; strip < 4 && stem.size() > 1; ++strip) {
            char last = stem.back();
            if (!std::isdigit(static_cast<unsigned char>(last)) && std::ispunct(static_cast<unsigned char>(last)) == 0) break;
            stem.pop_back();
            if (stem.size() >= 3 && in_list(stem)) return true;
        }
    }
    return false;
}

const char *rating_name(Rating r) {
    switch (r) {
        case Rating::VeryWeak: return "Very Weak";
        case Rating::Weak: return "Weak";
        case Rating::Moderate: return "Moderate";
        case Rating::Strong: return "Strong";
        case Rating::VeryStrong: return "Very Strong";
    }
    return "Unknown";
}

std::string format_duration(double seconds) {
    char buf[64];
    if (seconds < 1) return "instantly";
    if (seconds < 60) { std::snprintf(buf, sizeof buf, "%.0f seconds", seconds); return buf; }
    if (seconds < 3600) { std::snprintf(buf, sizeof buf, "%.0f minutes", seconds / 60); return buf; }
    if (seconds < 86400) { std::snprintf(buf, sizeof buf, "%.0f hours", seconds / 3600); return buf; }
    if (seconds < 31557600) { std::snprintf(buf, sizeof buf, "%.0f days", seconds / 86400); return buf; }
    double years = seconds / 31557600;
    if (years < 1000) { std::snprintf(buf, sizeof buf, "%.0f years", years); return buf; }
    if (years < 1e6) { std::snprintf(buf, sizeof buf, "%.0f thousand years", years / 1e3); return buf; }
    return "more than a million years";
}

Analysis analyze(const std::string &password) {
    Analysis a;
    a.length = password.size();

    for (char ch : password) {
        unsigned char c = static_cast<unsigned char>(ch);
        if (c >= 128 || std::iscntrl(c)) a.other++;
        else if (std::isupper(c)) a.upper++;
        else if (std::islower(c)) a.lower++;
        else if (std::isdigit(c)) a.digits++;
        else a.symbols++;  // printable ASCII punctuation and space
    }
    a.pool_size = (a.lower ? 26 : 0) + (a.upper ? 26 : 0) + (a.digits ? 10 : 0) +
                  (a.symbols ? 33 : 0) + (a.other ? 32 : 0);

    Patterns p = find_patterns(password);
    a.longest_repeat = p.longest_repeat;
    a.longest_run = p.longest_run;
    for (size_t i = 0; i < password.size(); ++i) {
        if (!p.free[i]) a.effective_length += 1.0;
    }

    a.raw_bits = a.pool_size > 1 ? a.effective_length * std::log2(static_cast<double>(a.pool_size)) : 0.0;
    a.bits = a.raw_bits;

    a.common = is_common(password);
    constexpr double kCommonCapBits = 10.0;  // a top list is exhausted in about a thousand guesses
    if (a.common) a.bits = std::min(a.bits, kCommonCapBits);

    if (a.bits < 28) a.rating = Rating::VeryWeak;
    else if (a.bits < 40) a.rating = Rating::Weak;
    else if (a.bits < 60) a.rating = Rating::Moderate;
    else if (a.bits < 80) a.rating = Rating::Strong;
    else a.rating = Rating::VeryStrong;

    // Average case: an attacker finds it after searching half the space.
    a.crack_seconds = a.bits <= 1 ? 0.0 : std::pow(2.0, a.bits - 1.0) / kAssumedGuessesPerSecond;

    if (a.common) a.suggestions.push_back("This is, or is a small variation of, a very common password. Change it entirely.");
    if (a.length < 12) a.suggestions.push_back("Make it longer: 12 or more characters, ideally a random passphrase of 4+ words.");
    if (a.longest_repeat >= 3) a.suggestions.push_back("Avoid repeated characters such as 'aaaa'.");
    if (a.longest_run >= 3) a.suggestions.push_back("Avoid runs such as 'abc', '321' or 'qwerty'.");
    if (a.length >= 12 && a.pool_size < 36 && !a.common) a.suggestions.push_back("Mixing in other kinds of character helps less than extra length, but it does help.");
    if (a.suggestions.empty()) a.suggestions.push_back("Looks fine. Use a password manager so every account gets a unique one.");
    return a;
}

}  // namespace pwa
