# pseudo code
import sys

sys.path.append("../algorithm/");
from Stack import *

# Extract root checker methods
    AntiRootMethod = list()
    test = []

    for cls in AntiRootList: # target class list iteration
        targetLineList = app.get_class(cls).code.splitlines()
        
        MethodList = app.get_class(cls).methods
        for i in range(len(MethodList)):
            MethodList[i] = MethodList[i].name
        MethodList = OrderedSet(MethodList)

        MethodIndex = 0

        StackMethodEnd = Stack()
        MethodEndFlag = False

        RootCheckerFlag = False

        for targetLine in targetLineList:

            # Check Flag
            if MethodEndFlag:
                StackMethodEnd = Stack()
                MethodEndFlag = False

                if RootCheckerFlag:
                    AntiRootMethod.append(MethodList[MethodIndex - 1])
                    RootCheckerFlag = False
                    
                                                                   
            # deal open & closing
            for iter in targetLine:
                if iter is '{':
                    StackMethodEnd.push(iter)
                elif iter is '}':
                    StackMethodEnd.pop()

            for rootfile in rootFiles:
                if rootfile in targetLine:
                    rootFile.append(MethodList[MethodIndex])
                    RootCheckerFlag = True
            
            # Check Method End
            if StackMethodEnd.isEmpty(): # if Method End
                MethodEndFlag = True
                MethodIndex += 1 # Search Next Method
    
    os.system('clear')
    print("Done.")
    print(AntiRootMethod)
    print(MethodIndex)
    print(MethodList)
    print(test)