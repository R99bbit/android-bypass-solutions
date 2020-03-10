import string

def extract_strings(filename, min=4):
    with open(filename, errors="ignore") as f:  # Python 3.x
        result = ""
        for c in f.read():
            if c in string.printable:
                result += c
                continue
            if len(result) >= min:
                yield result
            result = ""
        if len(result) >= min:  # catch result at EOF
            yield result

if __name__ == "__main__":
    print(extract_strings('../jni/x86/libbpsec.so'))