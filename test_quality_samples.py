"""
Test file containing examples of code quality issues
This file is intentionally written with quality problems for testing purposes
"""

import time


# ============================================
# 1. EMPTY CATCH BLOCKS
# ============================================

def example_empty_catch_1():
    """Example of empty catch block"""
    try:
        risky_operation()
    except Exception:
        pass  # BAD: Empty catch block!


def example_empty_catch_2():
    """Another empty catch"""
    try:
        data = open("file.txt").read()
    except:
        # TODO: Handle this later
        pass


# ============================================
# 2. INFINITE LOOPS
# ============================================

def example_infinite_loop_1():
    """Example of infinite loop without break"""
    while True:
        print("This will run forever!")
        time.sleep(1)
        # Missing break condition!


def example_infinite_loop_2():
    """Another infinite loop"""
    counter = 0
    while 1:
        counter += 1
        # No break or return!


# ============================================
# 3. DEAD/UNREACHABLE CODE
# ============================================

def example_dead_code_1():
    """Example of unreachable code after return"""
    x = 10
    if x > 5:
        return True
        print("This will never execute!")  # DEAD CODE!
        x = 20  # Also dead code
    return False


def example_dead_code_2():
    """More dead code"""
    for i in range(10):
        if i == 5:
            return i
            print(f"Found {i}")  # Dead code


def example_dead_code_3():
    """Dead code after break"""
    while True:
        break
        print("Never reached")  # Dead code


# ============================================
# 4. INCONSISTENT NAMING
# ============================================

# Good Python convention: snake_case
def good_function_name():
    pass


# Bad: Using camelCase in Python (should be snake_case)
def BadFunctionName():  # Should be PascalCase for classes only
    pass


# Bad: Mixed conventions
def myFunction():  # camelCase instead of snake_case
    my_variable = 10  # Good
    MyOtherVar = 20   # Bad: Mixed case
    ANOTHER_VAR = 30  # Should be for constants only
    return my_variable


# Class naming issues
class my_class:  # Should be MyClass (PascalCase)
    def __init__(self):
        self.UserName = ""  # Should be user_name
        self.user_age = 0   # Good


class GoodClassName:  # Good: PascalCase
    def __init__(self):
        self.good_attribute = ""  # Good


# ============================================
# COMBINED ISSUES
# ============================================

def problematic_function():
    """This function has multiple quality issues"""
    
    # Issue 1: Infinite loop
    while True:
        try:
            # Issue 2: Empty catch
            result = perform_operation()
        except:
            pass  # Empty catch
        
        if result == "stop":
            return True
            print("Never executed")  # Issue 3: Dead code
    
    # Issue 4: Dead code after loop
    print("This is unreachable")
    return False


# Bad naming mixed with other issues
def ProcessData():  # Should be process_data
    """Bad naming and other issues"""
    MyList = []  # Should be my_list
    
    while 1:  # Infinite loop
        try:
            MyList.append(getData())
        except:
            pass  # Empty catch
        
        return MyList
        print("Dead code here")


# Helper functions to avoid import errors
def risky_operation():
    return 42


def perform_operation():
    return "continue"


def getData():
    return 1


if __name__ == "__main__":
    print("This file contains intentional quality issues for testing")
    print("Run quality_analyzer.py on this file to detect them!")

