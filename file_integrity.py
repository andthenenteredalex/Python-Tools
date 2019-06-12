# homemade fim. python hash_script2.py

# run manually or as scheduled task.
# run from a remote directory to ensure integrity. specify full path to the file you're checking for integrity in line 13
# does not open directories, only files.

from time import gmtime,strftime
from os import walk
import hashlib
import csv

# variables
mydirectory = r'C:\users\85510\security-tools'
hash_time_stamp = str(strftime("%Y-%m-%d %H:%M:%S", gmtime()))

# all file names
file_names_in_directory = []


for (dirpath, dirnames, filenames) in walk(mydirectory):
    file_names_in_directory.extend(filenames)
    break


# open previous hashes
with open('hash-outfile2.txt', 'r') as hash_outfile:
    reader = csv.reader(hash_outfile, delimiter='=')
    old_hashes = list(reader) # old_hashes stores in old_hashes variable

hash_outfile.close()


# writing new hashes to hash-outfile.txt
hash_outfile2 = open('hash-outfile2.txt', 'w')
for item in file_names_in_directory: # computing hashes
    item2 = r'%s\%s' % (mydirectory,item)
    with open(item2, "rb") as file:
        bytes = file.read()
        readable_hash = hashlib.sha256(bytes).hexdigest()
        item_var = '%s=%s\n' % (item2, readable_hash)
        hash_outfile2.write(item_var)
		
hash_outfile.close()


# open new hashes to compare to old hashes
with open('hash-outfile2.txt', 'r') as hash_outfile2:
    reader2 = csv.reader(hash_outfile2, delimiter='=')
    new_hashes = list(reader2) # new hashes stored in new_hashes variable

print('''########################################################''')
print('''######`     )###(        )####/  \#####/  \######   ####''')
print('''#####/    #########|   |#####`    #####    `#####   ####''')
print('''(          )#######|   |#####      ###      #####   ####''')
print('''#####+   +#########|   |#####   #   #   #   #####   ####''')
print('''######   ##########|   |#####   ##\   /##   ############''') 
print('''######   #######(        )###   #########   #####   ####''')
print('''########################################################''')
	    
      
# compares new hashes to old hashes 
for line in old_hashes:
    if line in new_hashes:
        print('good')
    else:
        print('%s ------> has been edited since last time this script ran' % line[0])		
