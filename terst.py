# Used to output the names of the files that need to be excluded by Source Trail
# of the chromium repository.
with open('lines.txt') as f:
    content = f.readlines()

    for line in content:
        line_contents = line.split("file:///Users/abdullahrasool/Documents/chromium/")
        print("../" + line_contents[1])