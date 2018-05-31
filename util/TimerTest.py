import time

TIMEOUT = 0.3263230323791504*1.10

flag_set = False
expired = False
start = time.time()

while not flag_set and not expired:
    if time.time()-start >= TIMEOUT:
        expired = True


print("Finished")
