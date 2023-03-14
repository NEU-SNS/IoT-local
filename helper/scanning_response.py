import os 
import sys
import csv

cur_out_dir = ""

with open(os.path.join(cur_out_dir,dev_file)) as f:
    lines = csv.reader(f)
    
    