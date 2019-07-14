import time

class Statistics:
    lap_time = []
    start_time = 0

    def __init__(self):
        pass

    def lap_start(self):
        self.start_time = time.time()
    
    def lap_end(self):
        end_time = time.time()
        self.lap_time.append(end_time - self.start_time)