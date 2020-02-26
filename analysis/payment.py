import pyjadx
import frida
import pygments
import os

def LoadDumpList():
    dump_code = {} # {key = className : value = code}

    dump_path = input("Target Path : android-auto-hack/dump-code/")
    dump_path = '../dump-code/' + dump_path
    try:
        print('[*] loading dump code')
        # loading dump code
        for root, dirs, files in os.walk(dump_path):
            for fname in files:
                full_fname = os.path.join(root, fname)
                class_name = ""
                # going class name
                class_name = full_fname.replace(dump_path + '/', "")
                class_name = class_name.replace('.java', "")
                dump_code[class_name] = open(full_fname).read()
    except Exception as e:
        print(e)

    return dump_code

def PaymentDetection():
    payment_class = []
    
    wordlist = open('payment_wordlist').read().split()
    dump_code = LoadDumpList()

    print('[*] Start Detection...')
    for iter_key in dump_code.keys():
        for iter_wordlist in wordlist:
            if iter_wordlist in dump_code[iter_key]:
                print(iter_key)
                payment_class.append(iter_key)
    
    return payment_class

if __name__ == "__main__":
    print(PaymentDetection())