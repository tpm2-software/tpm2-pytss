import re
import math

NUMBER = re.compile(r"([0-9]+)")
FORMATS = list(
    map(re.compile, [r"(\(\([0-9]+\+[0-9]+\)\/[0-9]+\))", r"(sizeof\(\w+\))"])
)


def calculate(module, string):
    for i, possible in enumerate(FORMATS):
        if not possible.fullmatch(string):
            continue
        if i == 0:
            one, two, three = map(int, NUMBER.findall(string))
            return math.ceil((one + two) / three)
        elif i == 1:
            type_name = string.replace("sizeof(", "").replace(")", "")
            sizeof_type_name = getattr(module, "sizeof_" + type_name)
            return sizeof_type_name
    return int(string)
