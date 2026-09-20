// Password strength estimator: a small, dependency-free C++17 library.
//
// The estimate is the size of the search space an attacker guessing at random would face,
// in bits, after discounting the parts a real attacker would not have to search: repeated
// characters, keyboard and alphabet runs, and passwords from a list of very common ones.
//
// It is an educational heuristic, not a guarantee. See the README for its limits.
#pragma once

#include <string>
#include <vector>

namespace pwa {

enum class Rating { VeryWeak, Weak, Moderate, Strong, VeryStrong };

struct Analysis {
    size_t length = 0;             // in bytes; the analyser is ASCII-focused
    int upper = 0, lower = 0, digits = 0, symbols = 0, other = 0;
    int pool_size = 0;             // size of the character set the password appears to draw from
    double effective_length = 0;   // length after discounting repeats and runs
    double raw_bits = 0;           // effective_length * log2(pool_size)
    double bits = 0;               // final estimate; capped for common passwords
    int longest_repeat = 0;        // longest run of one identical character
    int longest_run = 0;           // longest ascending or descending alphabet/keyboard run
    bool common = false;           // matches a very common password (possibly disguised)
    Rating rating = Rating::VeryWeak;
    double crack_seconds = 0;      // average time at kAssumedGuessesPerSecond
    std::vector<std::string> suggestions;
};

// Offline attack on a fast hash with a serious GPU rig. Slow hashes (bcrypt, Argon2) are far better.
constexpr double kAssumedGuessesPerSecond = 1e10;

Analysis analyze(const std::string &password);

const char *rating_name(Rating r);

// "instantly", "3 hours", "12 years", "more than a million years", and so on.
std::string format_duration(double seconds);

// True when the password, lower-cased and with common substitutions undone (@ to a, 0 to o, ...)
// and up to four trailing digits or symbols removed, is on the built-in common-password list.
bool is_common(const std::string &password);

}  // namespace pwa
