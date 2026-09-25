# Password Strength Analyzer

[![ci](https://github.com/jayraj0975/password-strength-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/jayraj0975/password-strength-analyzer/actions/workflows/ci.yml)

> **Educational estimator. Do not use it to decide whether a password is safe to use.** It rests on three assumptions,
> all stated below: one assumed attacker speed, a short built-in list of common passwords, and characters treated as
> if they were chosen at random.

A small C++17 library and command-line tool that estimates how hard a password is to guess. It has no
dependencies, never prints the password back, and is built with warnings as errors and tested under
AddressSanitizer and UBSan.

## How the estimate works

The score is the size of the search space, in **bits**, that an attacker guessing at random would face:
`effective length x log2(character pool)`. Two things make it better than counting character types:

- **Patterns are discounted, not rewarded.** Repeated blocks (`aaaa`), and ascending or descending runs along
  the alphabet, the digits, or a keyboard row (`abc`, `321`, `qwerty`), only count their first character.
  So `abcdefgh` and `aaaaaaaaaaaa` both score about 4.7 bits, where naive character counting would give about 38 and 56.
- **Very common passwords are capped at 10 bits.** A built-in list of well-known passwords is checked after
  lower-casing, undoing substitutions (`@`->a, `0`->o, `$`->s, ...) and stripping up to four trailing digits or
  symbols, so `P@ssw0rd`, `Password1` and `dragon2024` are caught, not just `password`.

Ratings by estimated bits: under 28 Very Weak, under 40 Weak, under 60 Moderate, under 80 Strong, otherwise Very Strong.
It also prints an average offline crack time, at an assumed 10^10 guesses per second against a fast hash.

## Try it

```bash
make test                # unit tests (ASan + UBSan)
make password_analyzer
./password_analyzer                  # interactive; input is hidden on a terminal
./password_analyzer --demo           # a few masked examples
./password_analyzer --rate 1e8       # assume a slower attacker (guesses per second)
./password_analyzer --compare-rates  # show the crack time at 1e8, 1e10 and 1e12 guesses per second
printf 'hunter2\nk9#Vq2$mLx8@Zp4!\n' | ./password_analyzer --stdin
```

```
  10.0 bits  Very Weak    7 chars  (common)
 105.1 bits  Very Strong  16 chars
```

The library is `include/password_analyzer.hpp` plus `src/password_analyzer.cpp`; call `pwa::analyze(password)`, or
`pwa::analyze(password, guesses_per_second)` to choose the attacker speed. The speed only changes the crack time, never
the bit estimate or the rating, and a rate that is not finite and positive throws `std::invalid_argument`.

The default of 10^10 guesses per second is **one assumed number, not "the" attacker speed**: it stands for an offline
attack on a fast hash with a serious GPU rig. Real attackers range far on both sides of it, which is why the rate is a
parameter and `--compare-rates` prints three.

## Limits, stated plainly

The three assumptions again, because they decide how far the number can be trusted:

1. **A fixed guess rate** (10^10 per second by default, configurable, never measured).
2. **A short built-in list of common passwords**, not a full dictionary or a breached-password corpus.
3. **An entropy-style heuristic**, not a model of how real cracking tools work (they use dictionaries, rules, keyboard
   walks, leaked passwords and per-target guesses).

- **It is an upper bound, and an educational one.** It assumes characters are chosen at random. Human-chosen
  passwords are far weaker: `Tr0ub4dor&3` gets about 72 bits here, but it is a dictionary word with common substitutions
  and falls much sooner to a real attacker. Only the short built-in list is checked, not a full dictionary or leaked-password corpus.
- **Length is counted in bytes** and non-ASCII characters are treated as one broad class, so it is ASCII-focused.
- **The crack time depends on the hash.** Slow password hashes (bcrypt, scrypt, Argon2) are much harder to attack than the
  fast hash assumed here.
- **Do not use it as a gate for real systems.** Use a maintained library such as zxcvbn, and check candidates against a
  breached-password list.

## History

The first version scored `ThisIsALongPassphrase1!` as merely "Weak" and could barely ever reach "Strong", penalised
unbalanced brackets (unrelated to strength), had no common-password check, only saw ascending runs, and read the
password with the input visible. This rewrite fixes those and adds tests and CI.

## License

MIT
