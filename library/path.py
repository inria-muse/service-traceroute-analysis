from os import listdir
from os.path import isfile, join

def get_files(init_dir):
    return [join(init_dir, f) for f in listdir(init_dir) if isfile(join(init_dir, f))]

def get_file(filename):
    return filename[filename.rindex("/")+1:]

def get_file_without_format(filename):
    string = filename[:filename.rindex(".")]
    if string[-2:] == "ps":
        return string[:-3]
    return string

def get_file_without_2_format(filename):
    string = filename[:filename.rindex(".")]
    string = string[:string.rindex(".")]
    return string
def get_dirs(init_dir):
    return [join(init_dir, f) for f in listdir(init_dir) if not isfile(join(init_dir, f))]

def get_allfiles(init_dir):
    files = []
    for directory in get_dirs(init_dir):
        files.extend(get_files(directory))
    return files