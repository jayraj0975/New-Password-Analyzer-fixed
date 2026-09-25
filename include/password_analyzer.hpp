// Password strength estimator: a small, dependency-free C++17 library.
//
// The estimate is the size of the search space an attacker guessing at random would face,
// in bits, after discounting the parts a real attacker would not have to search: repeated
// characters, keyboard and alphabet runs, and passwords from a list of very common ones.
//
// It is an educational heuristic, NOT a tool for deciding whether a password is safe to use. Its assumptions
// (a fixed guess rate, a short built-in common-password list, characters treated as chosen at random) are
// stated in the README.
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
    double crack_seconds = 0;      // average time at guesses_per_second
    double guesses_per_second = 0; // the attacker speed crack_seconds assumes (an assumption, not a measurement)
    std::vector<std::string> suggestions;
};

// The default attacker speed: an offline attack on a fast hash with a serious GPU rig. It is one assumed
// number, not "the" attacker speed; slow password hashes (bcrypt, scrypt, Argon2) are far harder to attack.
constexpr double kAssumedGuessesPerSecond = 1e10;

// Analyses `password`. `guesses_per_second` only affects crack_seconds (never bits or the rating), so
// callers can compare attacker speeds. Throws std::invalid_argument unless it is finite and positive.
Analysis analyze(const std::string &password, double guesses_per_second = kAssumedGuessesPerSecond);

// Average time to find a password worth `bits` bits, at `guesses_per_second` (half the space is searched
// on average). Throws std::invalid_argument unless the rate is finite and positive.
double crack_seconds(double bits, double guesses_per_second);

const char *rating_name(Rating r);

// "instantly", "3 hours", "12 years", "more than a million years", and so on.
std::string format_duration(double seconds);

// True when the password, lower-cased and with common substitutions undone (@ to a, 0 to o, ...)
// and up to four trailing digits or symbols removed, is on the built-in common-password list.
bool is_common(const std::string &password);

}  // namespace pwa
