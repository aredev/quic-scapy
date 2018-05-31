with open('code.txt') as f:
    content = f.readlines()

correct_code = ""
for line in content:
    line_of_code = line
    line_of_code.replace("    ", "\t")
    if "PacketField" in line:
        components = line.split("\"")
        line_of_code = "\t\tStrFixedLenField(\"{}\", \"{}\", {}),\n".format(components[1], components[3], str(len(components[3].replace("\'", ""))))
    correct_code += line_of_code
print(correct_code)
