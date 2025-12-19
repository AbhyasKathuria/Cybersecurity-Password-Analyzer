import zxcvbn
import argparse
import itertools
import datetime
import nltk
import math
import os
import tkinter as tk
from tkinter import messagebox, filedialog

# Auto-download NLTK 'words' corpus if not present
nltk.download('words', quiet=True)

def calculate_entropy(password):
    """Custom entropy calculation in bits"""
    charset_size = 0
    if any(c.islower() for c in password): charset_size += 26
    if any(c.isupper() for c in password): charset_size += 26
    if any(c.isdigit() for c in password): charset_size += 10
    if any(not c.isalnum() for c in password): charset_size += 32  # symbols
    if charset_size == 0:
        return 0
    return len(password) * math.log2(charset_size)

def analyze_password(password):
    """Analyze password using zxcvbn and custom entropy"""
    result = zxcvbn.zxcvbn(password)
    score = result['score']  # 0-4
    crack_time = result['crack_times_display']['offline_slow_hashing_1e4_per_second']
    entropy = calculate_entropy(password)
    feedback = result['feedback']['suggestions']
    warning = result['feedback']['warning']
    
    return {
        'score': score,
        'crack_time': crack_time,
        'entropy': f"{entropy:.2f} bits",
        'warning': warning if warning else "No warning.",
        'feedback': ' | '.join(feedback) if feedback else "Strong password! No suggestions."
    }

def generate_leetspeak(word):
    """Generate common leetspeak variations"""
    leet_map = {
        'a': ['@', '4'], 'e': ['3'], 'i': ['1', '!', '|'],
        'o': ['0'], 's': ['$', '5'], 't': ['7', '+']
    }
    variations = [word]
    for char, subs in leet_map.items():
        lower_char = char
        upper_char = char.upper()
        if lower_char in word.lower():
            new_vars = []
            for var in variations:
                for sub in subs:
                    new_var = var.replace(lower_char, sub).replace(upper_char, sub.upper())
                    new_vars.append(new_var)
            variations.extend(new_vars)
    return list(set(variations))  # Remove duplicates

def generate_wordlist(inputs, use_nltk=False):
    """Generate custom wordlist from user inputs"""
    if not inputs:
        return []
    
    wordlist = set(inputs)
    current_year = datetime.datetime.now().year
    
    for base in list(inputs):
        # Basic transformations
        wordlist.add(base.upper())
        wordlist.add(base.lower())
        wordlist.add(base.capitalize())
        wordlist.add(base[::-1])  # reversed
        
        # Leetspeak
        wordlist.update(generate_leetspeak(base))
        
        # Append/prepend years (last 15 years + next 5)
        for year in range(current_year - 15, current_year + 6):
            wordlist.add(f"{base}{year}")
            wordlist.add(f"{year}{base}")
        
        # Append common numbers
        for num in ['123', '1234', '!', '@', '#', '2025', '']:
            wordlist.add(f"{base}{num}")
            wordlist.add(f"{num}{base}")
    
    # Pairwise combinations (e.g., name + pet)
    for combo in itertools.permutations(inputs, 2):
        wordlist.add(''.join(combo))
        wordlist.add(' '.join(combo))
        wordlist.add('-'.join(combo))
        wordlist.add('_'.join(combo))
    
    # Add common English words from NLTK if requested
    if use_nltk:
        common_words = set(w.lower() for w in nltk.corpus.words.words()[:1000])  # Top 1000
        wordlist.update(common_words)
    
    return sorted(list(wordlist))

def export_wordlist(wordlist, filename='custom_wordlist.txt'):
    """Save wordlist to file"""
    with open(filename, 'w', encoding='utf-8') as f:
        f.write('\n'.join(wordlist))
    print(f"\nWordlist exported to: {os.path.abspath(filename)} ({len(wordlist)} entries)")

# ==================== CLI MODE ====================
parser = argparse.ArgumentParser(description="Password Strength Analyzer & Custom Wordlist Generator")
parser.add_argument("--analyze", type=str, help="Password to analyze")
parser.add_argument("--generate", nargs="+", help="Inputs for wordlist (e.g., name birthyear pet city)")
parser.add_argument("--use_nltk", action="store_true", help="Add common English words from NLTK")
parser.add_argument("--export", default="custom_wordlist.txt", help="Output filename for wordlist")
args = parser.parse_args()

if args.analyze:
    print("\n=== PASSWORD ANALYSIS ===\n")
    analysis = analyze_password(args.analyze)
    print(f"Password      : {args.analyze}")
    print(f"Strength Score: {analysis['score']}/4")
    print(f"Crack Time    : {analysis['crack_time']}")
    print(f"Entropy       : {analysis['entropy']}")
    print(f"Warning       : {analysis['warning']}")
    print(f"Suggestions   : {analysis['feedback']}\n")

if args.generate:
    print("\n=== GENERATING WORDLIST ===\n")
    wordlist = generate_wordlist(args.generate, args.use_nltk)
    export_wordlist(wordlist, args.export)

# ==================== GUI MODE (if no arguments) ====================
if not (args.analyze or args.generate):
    # GUI Functions
    def run_analysis():
        password = entry_pass.get()
        if not password:
            messagebox.showwarning("Input Required", "Please enter a password!")
            return
        analysis = analyze_password(password)
        result_text.set(
            f"Score: {analysis['score']}/4\n"
            f"Crack Time: {analysis['crack_time']}\n"
            f"Entropy: {analysis['entropy']}\n"
            f"Warning: {analysis['warning']}\n"
            f"Suggestions: {analysis['feedback']}"
        )

    def run_generate():
        input_text = entry_inputs.get().strip()
        if not input_text:
            messagebox.showwarning("Input Required", "Enter inputs separated by commas!")
            return
        inputs = [item.strip() for item in input_text.split(',')]
        use_nltk_var = nltk_check.get()
        wordlist = generate_wordlist(inputs, use_nltk_var)
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile="custom_wordlist.txt"
        )
        if filename:
            export_wordlist(wordlist, filename)
            messagebox.showinfo("Success", f"Wordlist saved!\n{len(wordlist)} entries generated.")

    # GUI Window
    root = tk.Tk()
    root.title("Password Strength Analyzer & Wordlist Generator")
    root.geometry("600x500")
    root.configure(padx=20, pady=20)

    tk.Label(root, text="Password Strength Analyzer", font=("Arial", 16, "bold")).pack(pady=10)

    tk.Label(root, text="Enter Password to Analyze:").pack()
    entry_pass = tk.Entry(root, width=50, show="*")
    entry_pass.pack(pady=5)

    tk.Button(root, text="Analyze Password", command=run_analysis, bg="#4CAF50", fg="white").pack(pady=10)

    result_text = tk.StringVar()
    result_text.set("Results will appear here...")
    tk.Label(root, textvariable=result_text, justify="left", bg="lightgray", width=60, height=8).pack(pady=10)

    tk.Label(root, text="Custom Wordlist Generator", font=("Arial", 14, "bold")).pack(pady=(20,10))
    tk.Label(root, text="Enter personal info (comma-separated): e.g., john, 1995, tiger, delhi").pack()
    entry_inputs = tk.Entry(root, width=60)
    entry_inputs.pack(pady=5)

    nltk_check = tk.BooleanVar()
    tk.Checkbutton(root, text="Include common English words (from NLTK)", variable=nltk_check).pack()

    tk.Button(root, text="Generate & Save Wordlist", command=run_generate, bg="#2196F3", fg="white").pack(pady=15)

    root.mainloop()