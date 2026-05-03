import sys

def parse_passphrase(passphrase, wordlist):
    # This tries to match from left to right greedily.
    # Actually, we know WORDLIST has hyphenated words.
    words = sorted(wordlist, key=len, reverse=True)
    # The current test does a simple substring replacement:
    # "down-drop-drop-short".replace("short", "", 1) -> "down-drop-drop-"
    # .replace("down", "", 1) -> "-drop-drop-"
    # .replace("drop", "", 1) -> "--drop-"
    # matched = 3. Because it only replaces "drop" ONCE.
    # Ah! The test loop is `for word in sorted_words: if word in remaining: replace(word, "", 1)`.
    # It only finds ONE instance of each word! If the passphrase has duplicate words (e.g. "drop-drop"), it only counts the first one.
    pass
