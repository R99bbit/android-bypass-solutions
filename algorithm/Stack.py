# stack using list
class Stack(list):
    def __init__(self):
        self.stack = []

    def push(self, data):
        self.stack.append(data)
    
    def pop(self):
        if self.isEmpty():
            return -1
        return self.stack.pop()

    def isEmpty(self):
        if len(self.stack) == 0:
            return True
        return False

# stack test
if __name__ == "__main__":
    s = Stack()

    s.push(4)
    print(s.pop())