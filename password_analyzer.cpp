#include <iostream>
#include <vector>
#include <string>
#include <stack>
#include <algorithm>
#include <cmath>
#include <iomanip>
#include <cctype>
#include <limits>

using namespace std;

bool balanced_brackets(const string &s) {
    stack<char> st;
    for (char c : s) {
        if (c == '(' || c == '{' || c == '[') st.push(c);
        else if (c == ')' || c == '}' || c == ']') {
            if (st.empty()) return false;
            char t = st.top(); st.pop();
            if ((c == ')' && t != '(') || (c == ']' && t != '[') || (c == '}' && t != '{')) return false;
        }
    }
    return st.empty();
}

int max_repeated_block(const string &s) {
    if (s.empty()) return 0;
    int maxb = 1, cur = 1;
    for (size_t i = 1; i < s.size(); ++i) {
        if (s[i] == s[i - 1]) cur++;
        else { maxb = max(maxb, cur); cur = 1; }
    }
    return max(maxb, cur);
}

int max_sequential_run(const string &s) {
    if (s.empty()) return 0;
    int best = 1, cur = 1;
    for (size_t i = 1; i < s.size(); ++i) {
        if ((int)s[i] == (int)s[i - 1] + 1) cur++;
        else cur = 1;
        best = max(best, cur);
    }
    return best;
}

double simple_entropy_score(int kinds, int length) {
    if (length <= 1) return 0.0;
    return kinds * log2((double)length);
}

string classify_score(double score) {
    if (score < 10) return "Very Weak";
    if (score < 20) return "Weak";
    if (score < 35) return "Moderate";
    if (score < 55) return "Strong";
    return "Very Strong";
}

struct Analysis {
    int len = 0, upper = 0, lower = 0, digits = 0, special = 0;
    bool balanced = true;
    int max_repeat = 1, max_seq = 1;
    double score = 0.0;
    string classification;
    vector<string> suggestions;
};

Analysis analyze_password(const string &pwd) {
    Analysis a;
    a.len = pwd.size();
    
    for (char c : pwd) {
        if (isupper((unsigned char)c)) a.upper++;
        else if (islower((unsigned char)c)) a.lower++;
        else if (isdigit((unsigned char)c)) a.digits++;
        else a.special++;
    }

    a.balanced = balanced_brackets(pwd);
    a.max_repeat = max_repeated_block(pwd);
    a.max_seq = max_sequential_run(pwd);

    int kinds = 0;
    kinds += (a.upper > 0);
    kinds += (a.lower > 0);
    kinds += (a.digits > 0);
    kinds += (a.special > 0);

    double base = simple_entropy_score(kinds, a.len);
    double penalty = 0.0;

    if (a.max_repeat >= 3) penalty += (a.max_repeat - 2) * 2.0;
    if (a.max_seq >= 3) penalty += (a.max_seq - 2) * 1.5;
    if (!a.balanced) penalty += 3.0;
    if (a.len < 8) penalty += (8 - a.len) * 1.5;

    a.score = max(0.0, base - penalty);
    a.classification = classify_score(a.score);

    if (a.len < 12) a.suggestions.push_back("Make it longer (12+ chars recommended).");
    if (a.upper == 0) a.suggestions.push_back("Add uppercase letters (A-Z).");
    if (a.lower == 0) a.suggestions.push_back("Add lowercase letters (a-z).");
    if (a.digits == 0) a.suggestions.push_back("Add digits (0-9).");
    if (a.special == 0) a.suggestions.push_back("Add special chars (!@#$%^&*).");
    if (a.max_repeat >= 3) a.suggestions.push_back("Avoid long repeated characters (like 'aaaa').");
    if (a.max_seq >= 3) a.suggestions.push_back("Avoid sequential patterns (like 'abc' or '123').");
    if (!a.balanced) a.suggestions.push_back("Fix unbalanced brackets/parentheses.");
    
    if (a.suggestions.empty() || (a.suggestions.size() == 1 && a.suggestions[0].find("Make it longer") != string::npos)) {
        a.suggestions.insert(a.suggestions.begin(), "Good! Consider using a passphrase for even better security.");
    }
    
    return a;
}

void print_report(const Analysis &a, const string &pwd) {
    cout << "Password Analysis Report\n";
    cout << "------------------------\n";
    cout << "Password (shown masked): ";
    for (size_t i = 0; i < pwd.size(); ++i) cout << '*';
    cout << "\nLength: " << a.len << "\n";
    cout << "Uppercase: " << a.upper << "  Lowercase: " << a.lower << "  Digits: " << a.digits << "  Special: " << a.special << "\n";
    cout << "Balanced brackets: " << (a.balanced ? "Yes" : "No") << "\n";
    cout << "Max repeated block: " << a.max_repeat << "\n";
    cout << "Max sequential run: " << a.max_seq << "\n";
    cout << fixed << setprecision(2);
    cout << "Score: " << a.score << "  Classification: " << a.classification << "\n";
    cout << "Suggestions:\n";
    for (auto &s : a.suggestions) cout << " - " << s << "\n";
    cout << "------------------------\n\n";
}

int main() {
    cout << "=== Password Strength Analyzer ===\n";
    
    while (true) {
        cout << "1. Analyze a password\n2. Batch test (quick demo)\n3. Exit\nChoose: ";
        int ch;

        if (!(cin >> ch)) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cout << "Invalid input. Please enter a number.\n";
            continue;
        }
        
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        
        if (ch == 1) {
            cout << "Enter password (visible): ";
            string pwd; 
            getline(cin, pwd);
            Analysis a = analyze_password(pwd);
            print_report(a, pwd);
        } else if (ch == 2) {
            vector<string> samples = {
                "password", "P@ss123", "Abcdef12", "Strong#Pass2025",
                "aaaa1111", "Qw!2eR$tY", "12345678", "Secur3!Pa$$",
                "ThisIsALongPassphrase1!", "()[]{}", "([)]"
            };
            cout << "\n--- Running Batch Tests ---\n";
            for (auto &s : samples) {
                Analysis a = analyze_password(s);
                print_report(a, s);
            }
        } else if (ch == 3) {
            cout << "Exit.\n";
            break;
        } else cout << "Invalid option.\n";
    }
    return 0;
}