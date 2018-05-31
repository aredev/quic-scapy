import os
import subprocess
import time

from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler


class ResetHandler(LoggingEventHandler):
    def on_created(self, event):
        print("Received reset request...")
        print("Killing server...")
        os.system('pkill -9 quic_server')
        time.sleep(4)
        print("Starting server...")
        subprocess.Popen('./start_quic.sh', cwd='/Users/abdullahrasool/Documents/chromium/src/')


handler = ResetHandler()
observer = Observer()
observer.schedule(handler, '../resets', False)
observer.start()
while True:
    pass
