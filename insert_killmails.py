import time
import datetime
start_time = time.time()
# your script
time.sleep(4)
elapsed_time = time.time() - start_time
print(time.strftime("%H:%M:%S", time.gmtime(elapsed_time)))