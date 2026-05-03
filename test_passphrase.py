import sys
import secrets

WORDLIST = ["short", "word", "drop", "drop-down", "down", "wordlist"]

def generate_passphrase(word_count: int = 4) -> str:
    words: list[str] = []
    max_val = (0x10000 // len(WORDLIST)) * len(WORDLIST)

    while len(words) < word_count:
        needed = word_count - len(words)
        rand_bytes = secrets.token_bytes(needed * 2)

        for i in range(0, needed * 2, 2):
            index = int.from_bytes(rand_bytes[i : i + 2], byteorder="little")
            if index < max_val:
                words.append(WORDLIST[index % len(WORDLIST)])
                if len(words) == word_count:
                    break

    return "-".join(words)

# test what the test is doing:
passphrase = generate_passphrase()
print(f"passphrase: {passphrase}")
word_set = set(WORDLIST)
remaining = passphrase
matched = 0
for word in sorted(word_set, key=len, reverse=True):
    if str(word) in remaining:
        print(f"found: {word}")
        remaining = remaining.replace(str(word), "", 1)
        matched += 1
print(f"matched: {matched}, remaining: {remaining}")
