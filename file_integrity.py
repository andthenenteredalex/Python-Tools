# home-made fim. python hash_script2.py

# run manually or as scheduled task.
# run from a remote directory. specify full path to the directory you're checking for integrity in line 12
# does not open directories, only hashes files.

from time import gmtime,strftime
from os import walk
import hashlib
import csv

mydirectory = r'C:\users\Alex\security-tools' # directory for integrity check. checks each file in this directory
hash_time_stamp = str(strftime("%Y-%m-%d %H:%M:%S", gmtime())) # timestamp

all_files_found_in_specified_folder = []

for (dirpath, dirnames, filenames) in walk(mydirectory):
    file_names_in_directory.extend(filenames)
    break

# open file with hashes from last run
with open('hash-outfile2.txt', 'r') as hash_outfile2:
    reader = csv.reader(hash_outfile2, delimiter='=')
    old_hashes = list(reader) # old_hashes stores in old_hashes variable
hash_outfile2.close()

# writing new hashes to hash-outfile2.txt
hash_outfile2 = open('hash-outfile2.txt', 'w')
for item in all_files_found_in_specified_folder: # computing hashes
    item2 = r'%s\%s' % (mydirectory,item)
    with open(item2, "rb") as file:
        bytes = file.read()
        readable_hash = hashlib.sha256(bytes).hexdigest()
        item_var = '%s=%s\n' % (item2, readable_hash)
        hash_outfile2.write(item_var)		
hash_outfile2.close()

# open new hashes to compare to old hashes
with open('hash-outfile2.txt', 'r') as hash_outfile2:
    reader2 = csv.reader(hash_outfile2, delimiter='=')
    new_hashes = list(reader2) # new hashes stored in new_hashes variable
hash_outfile2.close()

print('''#########################################################''')
print('''######`     )###(         )####/  \#####/  \######   ####''')
print('''#####/    #########|   |######`    #####    `#####   ####''')
print('''(          )#######|   |######      ###      #####   ####''')
print('''#####+   +#########|   |######   #   #   #   #####   ####''')
print('''######   ##########|   |######   ##\   /##   ############''') 
print('''######   #######(         )###   #########   #####   ####''')
print('''#########################################################''')
	    
# compares new hashes to old hashes 
for line in old_hashes:
    if line in new_hashes:
        print('good')
    else:
        print('%s ------> has been edited since last time this script ran' % line[0])		
