# Runs the decompiler to collect variable names from binaries containing
# debugging information, then strips the binaries and injects the collected
# names into that decompilation output.
# This generates an aligned, parallel corpus for training translation models.

# Requires Python 3

import argparse
import datetime
import errno
import multiprocessing
import pickle
import os
import subprocess
import sys
import tempfile
import tqdm

statyre_dir = os.path.dirname(os.path.abspath(__file__))
COLLECT = os.path.join(statyre_dir, 'decompiler_scripts', 'collect.py')
DUMP_TREES = os.path.join(statyre_dir, 'decompiler_scripts', 'dump_trees.py')
TIMEOUT=300

parser = argparse.ArgumentParser(description="Run the decompiler to generate a corpus.")
parser.add_argument('--ida',
                    metavar='IDA',
                    help="location of the idat64 binary",
                    default='/home/jlacomis/bin/ida/idat64',
)
parser.add_argument('binaries_dir',
                    metavar='BINARIES_DIR',
                    help="directory containing binaries",
)
parser.add_argument('output_dir',
                    metavar='OUTPUT_DIR',
                    help="output directory",
)

args = parser.parse_args()
env = os.environ.copy()
env['IDALOG'] = '/dev/stdout'

# Check for/create output directories
output_dir = os.path.abspath(args.output_dir)
env['OUTPUT_DIR'] = output_dir

def make_directory(dir_path):
    """Make a directory, with clean error messages."""
    try:
        os.makedirs(dir_path)
    except OSError as e:
        if not os.path.isdir(dir_path):
            raise NotADirectoryError(f"'{dir_path}' is not a directory")
        if e.errno != errno.EEXIST:
            raise

make_directory(output_dir)

# Use RAM-backed memory for tmp if available
if os.path.exists('/dev/shm'):
    tempfile.tempdir = '/dev/shm'

def run_decompiler(file_name, env, script, timeout=None):
    """Run a decompiler script.

    Keyword arguments:
    file_name -- the binary to be decompiled
    env -- an os.environ mapping, useful for passing arguments
    script -- the script file to run
    timeout -- timeout in seconds (default no timeout)
    """
    idacall = [args.ida, '-B', f'-S{script}', file_name]
    output = ''
    try:
        output = subprocess.check_output(idacall, env=env, timeout=timeout)
    except subprocess.CalledProcessError as e:
        output = e.output
        subprocess.call(['rm', '-f', f'{file_name}.i64'])
    return output

def do_file(binary):
    # Create a new temporary directory for this file. This is needed
    # to delete the .i64 files that come from IDA
    with tempfile.TemporaryDirectory() as tempdir:
        start = datetime.datetime.now()
        #print(f"Started: {start}")
        env['PREFIX'] = binary
        file_path = os.path.join(args.binaries_dir, binary)
        #print(f"Collecting from {file_path}")
        with tempfile.NamedTemporaryFile() as collected_vars:
            # First collect variables
            env['COLLECTED_VARS'] = collected_vars.name
            with tempfile.NamedTemporaryFile(dir=tempdir) as orig:
                subprocess.check_output(['cp', file_path, orig.name])
                # Timeout after 30 seconds for first run
                try:
                    run_decompiler(orig.name, env, COLLECT, timeout=TIMEOUT)
                except subprocess.TimeoutExpired:
                    print(f"{file_path} Timed out\n")
                    return
                try:
                    if not pickle.load(collected_vars):
                        print(f"No variables collected from {file_path}\n")
                        return
                except:
                    print(f"No variables collected from {file_path}\n")
                    return
            # Make a new stripped copy and pass it the collected vars
            try:
                with tempfile.NamedTemporaryFile(dir=tempdir) as stripped:
                    subprocess.call(['rm', stripped.name])
                    subprocess.call(['strip', '--strip-unneeded', file_path, '-o', stripped.name])
                    if not os.path.exists(stripped.name):
                        print(f"Stripping ${file_path} failed\n")
                        return
                    #print(f"{binary} stripped")
                    # Dump the trees.
                    # No timeout here, we know it'll run in a reasonable amount of
                    # time and don't want mismatched files
                    run_decompiler(stripped.name, env, DUMP_TREES)
            except FileNotFoundError:
                pass
        #end = datetime.datetime.now()
        #duration = end-start
        #print(f"Duration: {duration}\n")

# Create a temporary directory, since the decompiler makes a lot of additional
# files that we can't clean up from here
with tempfile.TemporaryDirectory() as tempdir:
    tempfile.tempdir = tempdir

    tasks = os.listdir(args.binaries_dir)

    pool = multiprocessing.Pool()
    for _ in tqdm.tqdm(pool.imap_unordered(do_file, tasks), smoothing=0.0, total=len(tasks)):
        pass
