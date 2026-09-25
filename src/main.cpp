#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

#include "password_analyzer.hpp"

#if defined(__unix__) || defined(__APPLE__)
#include <termios.h>
#include <unistd.h>
#define PWA_HAVE_TERMIOS 1
#endif

namespace {

// The attacker speed used for crack-time estimates; --rate changes it, --compare-rates adds a comparison.
double g_rate = pwa::kAssumedGuessesPerSecond;
bool g_compare_rates = false;

void print_report(const pwa::Analysis &a) {
    std::printf("Password Analysis\n-----------------\n");
    std::printf("Length:            %zu\n", a.length);
    std::printf("Character kinds:   lower %d, upper %d, digits %d, symbols %d, other %d\n",
                a.lower, a.upper, a.digits, a.symbols, a.other);
    std::printf("Longest repeat:    %d    Longest run: %d\n", a.longest_repeat, a.longest_run);
    std::printf("Common password:   %s\n", a.common ? "yes" : "no");
    std::printf("Estimated bits:    %.1f (assumes characters chosen at random)\n", a.bits);
    std::printf("Rating:            %s\n", pwa::rating_name(a.rating));
    std::printf("Average offline crack time at an ASSUMED %.0e guesses/s: %s\n",
                a.guesses_per_second, pwa::format_duration(a.crack_seconds).c_str());
    if (g_compare_rates) {
        for (double rate : {1e8, 1e10, 1e12})
            std::printf("  at %.0e guesses/s: %s\n", rate,
                        pwa::format_duration(pwa::crack_seconds(a.bits, rate)).c_str());
    }
    std::printf("Suggestions:\n");
    for (const std::string &s : a.suggestions) std::printf("  - %s\n", s.c_str());
    std::printf("Note: this is an upper bound. Passwords built from words, names or dates are\n"
                "      much weaker than the estimate, because attackers try those first.\n\n");
}

// Reads a line without echoing it when stdin is a terminal.
std::string read_hidden(const char *prompt) {
    std::cout << prompt << std::flush;
    std::string line;
#ifdef PWA_HAVE_TERMIOS
    if (isatty(STDIN_FILENO)) {
        termios old{};
        tcgetattr(STDIN_FILENO, &old);
        termios hidden = old;
        hidden.c_lflag &= static_cast<tcflag_t>(~ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &hidden);
        std::getline(std::cin, line);
        tcsetattr(STDIN_FILENO, TCSANOW, &old);
        std::cout << "\n";
        return line;
    }
#endif
    std::getline(std::cin, line);
    return line;
}

int run_stdin() {
    std::string line;
    while (std::getline(std::cin, line)) {
        pwa::Analysis a = pwa::analyze(line);
        // Never echo the password: only its length and the verdict.
        std::printf("%6.1f bits  %-11s  %zu chars%s\n", a.bits, pwa::rating_name(a.rating), a.length,
                    a.common ? "  (common)" : "");
    }
    return 0;
}

int run_demo() {
    const std::vector<std::string> samples = {
        "password", "P@ssw0rd", "12345678", "abcdefgh", "aaaaaaaaaaaa", "Tr0ub4dor&3",
        "Qw!2eR$tY", "Strong#Pass2025", "ThisIsALongPassphrase1!", "k9#Vq2$mLx8@Zp4!"};
    for (const std::string &s : samples) {
        pwa::Analysis a = pwa::analyze(s);
        std::printf("%-26s %6.1f bits  %-11s%s\n", std::string(s.size(), '*').c_str(), a.bits,
                    pwa::rating_name(a.rating), a.common ? "  (common)" : "");
    }
    std::printf("\nPasswords are masked. Estimates are upper bounds: \"Tr0ub4dor&3\" scores well here\n"
                "but is a dictionary word with substitutions, which real attackers try early.\n");
    return 0;
}

int interactive() {
    std::printf("=== Password Strength Analyzer ===\n");
    while (true) {
        std::printf("1. Analyze a password\n2. Demo\n3. Exit\nChoose: ");
        int choice = 0;
        if (!(std::cin >> choice)) {
            if (std::cin.eof()) return 0;
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::printf("Please enter a number.\n");
            continue;
        }
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        if (choice == 1) print_report(pwa::analyze(read_hidden("Enter password (hidden): "), g_rate));
        else if (choice == 2) run_demo();
        else if (choice == 3) return 0;
        else std::printf("Invalid option.\n");
    }
}

int usage(const char *prog, int code) {
    std::printf("Usage: %s [--rate N] [--compare-rates] [--stdin | --demo]\n"
                "  (no mode)         interactive menu, input hidden on a terminal\n"
                "  --stdin           read one password per line from stdin, print one verdict per line\n"
                "  --demo            score a few sample passwords\n"
                "  --rate N          assume an attacker making N guesses per second (default %.0e)\n"
                "  --compare-rates   also show the crack time at 1e8, 1e10 and 1e12 guesses per second\n"
                "\nAn educational estimator, not a tool for deciding whether a password is safe to use.\n",
                prog, pwa::kAssumedGuessesPerSecond);
    return code;
}

}  // namespace

int main(int argc, char **argv) {
    enum class Mode { Interactive, Stdin, Demo } mode = Mode::Interactive;
    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (!std::strcmp(arg, "--help")) return usage(argv[0], 0);
        if (!std::strcmp(arg, "--stdin")) mode = Mode::Stdin;
        else if (!std::strcmp(arg, "--demo")) mode = Mode::Demo;
        else if (!std::strcmp(arg, "--compare-rates")) g_compare_rates = true;
        else if (!std::strcmp(arg, "--rate")) {
            if (i + 1 >= argc) { std::fprintf(stderr, "--rate needs a number\n"); return 2; }
            char *end = nullptr;
            double rate = std::strtod(argv[++i], &end);
            if (end == argv[i] || *end != '\0' || !std::isfinite(rate) || rate <= 0) {
                std::fprintf(stderr, "--rate must be a finite number greater than zero, for example 1e10\n");
                return 2;
            }
            g_rate = rate;
        } else {
            std::fprintf(stderr, "unknown option: %s\n", arg);
            return usage(argv[0], 1);
        }
    }
    switch (mode) {
        case Mode::Stdin: return run_stdin();
        case Mode::Demo: return run_demo();
        case Mode::Interactive: break;
    }
    return interactive();
}
