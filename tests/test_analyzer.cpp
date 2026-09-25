// Dependency-free tests. Build and run with `make test`.
#include <cmath>
#include <cstdio>
#include <limits>
#include <stdexcept>
#include <string>

#include "password_analyzer.hpp"

static int failures = 0;
#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);   \
            ++failures;                                                   \
        }                                                                 \
    } while (0)

using namespace pwa;

int main() {
    // common passwords, including disguised ones
    CHECK(is_common("password"));
    CHECK(is_common("PASSWORD"));
    CHECK(is_common("P@ssw0rd"));
    CHECK(is_common("letmein!!"));
    CHECK(is_common("dragon2024"));
    CHECK(!is_common("k9#Vq2$mLx8@Zp4!"));
    CHECK(!is_common(""));
    CHECK(analyze("password").rating == Rating::VeryWeak);
    CHECK(analyze("P@ssw0rd").rating == Rating::VeryWeak);
    CHECK(analyze("password").bits <= 10.0);

    // patterns are discounted, not rewarded
    Analysis rep = analyze("aaaaaaaaaaaa");
    CHECK(rep.longest_repeat == 12);
    CHECK(rep.effective_length == 1.0);
    CHECK(rep.rating == Rating::VeryWeak);

    CHECK(analyze("abcdefgh").longest_run == 8);
    CHECK(analyze("hgfedcba").longest_run == 8);   // descending
    CHECK(analyze("qwertyui").longest_run == 8);   // keyboard row
    CHECK(analyze("13579246").longest_run < 3);
    CHECK(analyze("abcdefgh").rating == Rating::VeryWeak);

    // length beats decoration
    CHECK(analyze("k9#Vq2$mLx8@Zp4!").bits > analyze("Xq7#pL2!").bits);
    CHECK(analyze("k9#Vq2$mLx8@Zp4!").rating >= Rating::Strong);
    CHECK(analyze("xkqzjwmvbnhg").bits > analyze("xkqzjwm").bits);

    // adding a character never lowers the estimate for a non-patterned password
    double prev = 0;
    for (std::string s = "rT"; s.size() < 20; s += "%q3zJ9"[s.size() % 6]) {
        double bits = analyze(s).bits;
        CHECK(bits >= prev - 1e-9);
        prev = bits;
    }

    // character classes and pool size
    Analysis mix = analyze("aB3$");
    CHECK(mix.lower == 1 && mix.upper == 1 && mix.digits == 1 && mix.symbols == 1);
    CHECK(mix.pool_size == 26 + 26 + 10 + 33);
    CHECK(std::fabs(mix.raw_bits - 4 * std::log2(95.0)) < 1e-9);

    // edge cases must not crash
    Analysis empty = analyze("");
    CHECK(empty.length == 0 && empty.bits == 0.0 && empty.rating == Rating::VeryWeak);
    CHECK(!empty.suggestions.empty());
    CHECK(analyze(std::string(1000, 'x')).effective_length == 1.0);
    CHECK(analyze("caf\xc3\xa9 \xe2\x9c\x93 long-ish").other > 0);
    CHECK(analyze(std::string("a\0b", 3)).length == 3);

    // reporting helpers
    CHECK(format_duration(0.2) == "instantly");
    CHECK(format_duration(120) == "2 minutes");
    CHECK(format_duration(7200) == "2 hours");
    CHECK(format_duration(1e20) == "more than a million years");
    CHECK(std::string(rating_name(Rating::Strong)) == "Strong");
    CHECK(analyze("password").crack_seconds < 1.0);
    CHECK(analyze("k9#Vq2$mLx8@Zp4!").crack_seconds > 3.15e7 * 1000);  // more than a millennium

    // the assumed attacker speed is a parameter, and only changes the time, never the estimate
    Analysis slow = analyze("k9#Vq2$mLx8@Zp4!", 1e8);
    Analysis dflt = analyze("k9#Vq2$mLx8@Zp4!");
    Analysis fast = analyze("k9#Vq2$mLx8@Zp4!", 1e12);
    CHECK(dflt.guesses_per_second == kAssumedGuessesPerSecond);
    CHECK(analyze("k9#Vq2$mLx8@Zp4!", kAssumedGuessesPerSecond).crack_seconds == dflt.crack_seconds);
    CHECK(slow.bits == dflt.bits && fast.bits == dflt.bits && slow.rating == fast.rating);
    CHECK(std::fabs(slow.crack_seconds / dflt.crack_seconds - 100.0) < 1e-6);    // 100x slower attacker
    CHECK(std::fabs(dflt.crack_seconds / fast.crack_seconds - 100.0) < 1e-6);    // 100x faster attacker
    CHECK(slow.guesses_per_second == 1e8 && fast.guesses_per_second == 1e12);
    CHECK(crack_seconds(1.0, 1e10) == 0.0 && crack_seconds(0.0, 1e10) == 0.0);
    CHECK(std::fabs(crack_seconds(21.0, 1.0) - std::pow(2.0, 20.0)) < 1e-6);     // half of 2^21 guesses

    // an unusable rate is refused for every password, including the empty one
    const double bad_rates[] = {0.0, -1.0, std::numeric_limits<double>::quiet_NaN(),
                                std::numeric_limits<double>::infinity()};
    for (double bad : bad_rates) {
        bool threw = false;
        try { analyze("hunter2", bad); } catch (const std::invalid_argument &) { threw = true; }
        CHECK(threw);
        threw = false;
        try { analyze("", bad); } catch (const std::invalid_argument &) { threw = true; }
        CHECK(threw);
        threw = false;
        try { crack_seconds(40.0, bad); } catch (const std::invalid_argument &) { threw = true; }
        CHECK(threw);
    }

    if (failures == 0) std::printf("all tests passed\n");
    return failures == 0 ? 0 : 1;
}
