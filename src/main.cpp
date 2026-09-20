#include <cstdio>
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

void print_report(const pwa::Analysis &a) {
    std::printf("Password Analysis\n-----------------\n");
    std::printf("Length:            %zu\n", a.length);
    std::printf("Character kinds:   lower %d, upper %d, digits %d, symbols %d, other %d\n",
                a.lower, a.upper, a.digits, a.symbols, a.other);
    std::printf("Longest repeat:    %d    Longest run: %d\n", a.longest_repeat, a.longest_run);
    std::printf("Common password:   %s\n", a.common ? "yes" : "no");
    std::printf("Estimated bits:    %.1f (assumes characters chosen at random)\n", a.bits);
    std::printf("Rating:            %s\n", pwa::rating_name(a.rating));
    std::printf("Average offline crack time (%.0e guesses/s, fast hash): %s\n",
                pwa::kAssumedGuessesPerSecond, pwa::format_duration(a.crack_seconds).c_str());
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
        if (choice == 1) print_report(pwa::analyze(read_hidden("Enter password (hidden): ")));
        else if (choice == 2) run_demo();
        else if (choice == 3) return 0;
        else std::printf("Invalid option.\n");
    }
}

}  // namespace

int main(int argc, char **argv) {
    if (argc > 1) {
        if (!std::strcmp(argv[1], "--stdin")) return run_stdin();
        if (!std::strcmp(argv[1], "--demo")) return run_demo();
        std::printf("Usage: %s [--stdin | --demo]\n"
                    "  (no args)  interactive menu, input hidden on a terminal\n"
                    "  --stdin    read one password per line from stdin, print one verdict per line\n"
                    "  --demo     score a few sample passwords\n", argv[0]);
        return std::strcmp(argv[1], "--help") == 0 ? 0 : 1;
    }
    return interactive();
}
