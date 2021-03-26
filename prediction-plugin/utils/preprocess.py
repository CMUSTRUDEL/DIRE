#!/usr/bin/env python
"""
Usage:
    preprocess.py [options] TAR_FILES TARGET_FOLDER

Options:
    -h --help                  Show this screen.
    --shard-size=<int>         shard size [default: 3000]
    --test-file=<file>         test file
    --no-filtering             do not filter files
"""

import glob
import multiprocessing
import os
import random
import sys
import tarfile
from collections import Iterable
from multiprocessing import Process
from typing import Tuple

import numpy as np
import ujson as json
from docopt import docopt
from tqdm import tqdm
from utils.ast import SyntaxNode
from utils.code_processing import (
    annotate_type,
    canonicalize_code,
    canonicalize_constants,
    preprocess_ast,
    tokenize_raw_code,
)
from utils.dataset import Example, json_line_reader

all_functions = dict()  # indexed by binaries


def is_valid_example(example):
    try:
        is_valid = example.ast.size < 300 and len(example.variable_name_map) > 0
    except RecursionError:
        is_valid = False

    return is_valid


def generate_example(json_str, binary_file):
    tree_json_dict = json.loads(json_str)

    root = SyntaxNode.from_json_dict(tree_json_dict["ast"])

    preprocess_ast(root, code=tree_json_dict["raw_code"])
    code_tokens = tokenize_raw_code(tree_json_dict["raw_code"])
    tree_json_dict["code_tokens"] = code_tokens

    # add function name to the name field of the root block
    root.name = tree_json_dict["function"]
    root.named_fields.add("name")

    new_json_dict = root.to_json_dict()
    tree_json_dict["ast"] = new_json_dict
    json_str = json.dumps(tree_json_dict)

    example = Example.from_json_dict(
        tree_json_dict,
        binary_file=binary_file,
        json_str=json_str,
        code_tokens=code_tokens,
    )

    if True or is_valid_example(example):
        canonical_code = canonicalize_code(example.ast.code)
        example.canonical_code = canonical_code
        return example
    else:
        return None


def example_generator(json_queue, example_queue, args, consumer_num=1):
    enable_filter = not args["--no-filtering"]
    while True:
        payload = json_queue.get()
        if payload is None:
            break

        examples = []
        for json_str, meta in payload:
            tree_json_dict = json.loads(json_str)

            root = SyntaxNode.from_json_dict(tree_json_dict["ast"])
            # root_reconstr = SyntaxNode.from_json_dict(root.to_json_dict())
            # assert root == root_reconstr

            preprocess_ast(root, code=tree_json_dict["raw_code"])
            code_tokens = tokenize_raw_code(tree_json_dict["raw_code"])
            tree_json_dict["code_tokens"] = code_tokens

            # add function name to the name field of the root block
            root.name = tree_json_dict["function"]
            root.named_fields.add("name")

            new_json_dict = root.to_json_dict()
            tree_json_dict["ast"] = new_json_dict
            json_str = json.dumps(tree_json_dict)

            example = Example.from_json_dict(
                tree_json_dict, binary_file=meta, json_str=json_str
            )

            is_valid = is_valid_example(example) if enable_filter else True
            if is_valid:
                canonical_code = canonicalize_code(example.ast.code)
                example.canonical_code = canonical_code
                examples.append(example)

        example_queue.put(examples)

    for i in range(consumer_num):
        example_queue.put(None)

    print("example generator quit!")


def main(args):
    test_run = bool(args["--test-file"])
    if test_run:
        np.random.seed(1234)
        random.seed(1992)

    tgt_folder = args["TARGET_FOLDER"]
    pattern_list = args["TAR_FILES"].split(",")
    tar_files = []
    for pattern in pattern_list:
        tar_files.extend(glob.glob(pattern))
    print(tar_files)

    os.system(f'mkdir -p "{tgt_folder}/files"')
    num_workers = 14

    for tar_file in tar_files:
        print(f"read {tar_file}")
        valid_example_count = 0

        json_enc_queue = multiprocessing.Queue()
        example_queue = multiprocessing.Queue(maxsize=2000)

        json_loader = multiprocessing.Process(
            target=json_line_reader,
            args=(
                os.path.expanduser(tar_file),
                json_enc_queue,
                num_workers,
                False,
                False,
                "binary_file",
            ),
        )
        json_loader.daemon = True
        json_loader.start()

        example_generators = []
        for i in range(num_workers):
            p = multiprocessing.Process(
                target=example_generator, args=(json_enc_queue, example_queue, args, 1)
            )
            p.daemon = True
            p.start()
            example_generators.append(p)

        n_finished = 0
        while True:
            payload = example_queue.get()
            if payload is None:
                print("received None!")
                n_finished += 1
                if n_finished == num_workers:
                    break
                continue

            examples = payload

            if examples:
                json_file_name = examples[0].binary_file["file_name"].split("/")[-1]
                with open(os.path.join(tgt_folder, "files/", json_file_name), "w") as f:
                    for example in examples:
                        f.write(example.json_str + "\n")
                        all_functions.setdefault(json_file_name, dict())[
                            example.ast.compilation_unit
                        ] = example.canonical_code

                valid_example_count += len(examples)

        print("valid examples: ", valid_example_count)

        json_enc_queue.close()
        example_queue.close()

        json_loader.join()
        for p in example_generators:
            p.join()

    cur_dir = os.getcwd()
    all_files = glob.glob(os.path.join(tgt_folder, "files/*.jsonl"))
    sorted(all_files)  # sort all files by names
    all_files = list(all_files)
    file_num = len(all_files)
    print(f"{file_num} valid binary files.")

    def _dump_file(tgt_file_name, file_names, dev=False):
        with open(os.path.join(tgt_folder, "file_list.txt"), "w") as f:
            for file_name in file_names:
                last_file_name = file_name.split("/")[-1]
                f.write(last_file_name + "\n")

                with open(file_name) as fr:
                    all_lines = fr.readlines()

                replace_lines = []
                for line in all_lines:
                    json_dict = json.loads(line.strip())
                    if dev:
                        func_name = json_dict["function"]
                        canonical_code = all_functions[last_file_name][func_name]
                        func_name_in_train = False
                        func_body_in_train = False
                        if func_name in train_functions:
                            func_name_in_train = True
                            if canonical_code in train_functions[func_name]:
                                func_body_in_train = True

                        json_dict["test_meta"] = dict(
                            function_name_in_train=func_name_in_train,
                            function_body_in_train=func_body_in_train,
                        )
                    new_json_str = json.dumps(json_dict)
                    replace_lines.append(new_json_str.strip())

                with open(file_name, "w") as fw:
                    for line in replace_lines:
                        fw.write(line + "\n")

        os.chdir(os.path.join(tgt_folder, "files"))
        print("creating tar file...")
        os.system(f"tar cf ../{tgt_file_name} -T ../file_list.txt")
        os.chdir(cur_dir)

    if test_run:
        print("dumping dev files")
        _dump_dev_file("dev.tar", dev_files, dev=True)

        print("dumping test files")
        _dump_dev_file("test.tar", test_files, dev=True)
    else:
        print("dumping files")
        _dump_file("preprocessed.tar", all_files)



if __name__ == "__main__":
    args = docopt(__doc__)
    main(args)
