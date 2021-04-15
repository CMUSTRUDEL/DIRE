#!/usr/bin/env python
# Returns variable name predictions from JSONL read on stdin
# Requires Python 3

from ..neural_model.model.model import RenamingModel
from typing import Dict, List, Any
from ..neural_model.utils.dataset import Dataset
from ..neural_model.utils.evaluation import Evaluator
from ..neural_model.utils.preprocess import generate_example_for_prediction
import argparse
import datetime
import errno
import json
import numpy as np
import os
import pickle
import pprint
import random
import subprocess
import sys
import tempfile
import torch

parser = argparse.ArgumentParser(description="Returns variable name predictions from JSONL read on stdin.")
parser.add_argument('--model',
                    help="location of the model"
)

args = parser.parse_args()
examples = []
for line in sys.stdin:
    examples.append(generate_example_for_prediction(line, None))

examples = filter(None, examples)

def seed_stuff():
    # seed the RNG
    seed = 42
    torch.manual_seed(seed)
    np.random.seed(seed * 13 // 7)
    random.seed(seed * 17 // 7)
    sys.setrecursionlimit(7000)
    default_config = '{"decoder": {"remove_duplicates_in_prediction": true, "remove_identities_in_predictions": true} }'
    global extra_config
    extra_config = json.loads(default_config)

def decode(model: RenamingModel,
           examples,
           config: Dict):

    model.eval()
    all_examples = dict()

    with torch.no_grad():
        for line_num, example in enumerate(examples):
            rename_result = model.predict([example])[0]
            example_pred_accs = []
            top_rename_result = rename_result[0]
            for old_name, gold_new_name \
                in example.variable_name_map.items():
                pred = top_rename_result[old_name]
                pred_new_name = pred['new_name']
                var_metric = Evaluator.get_soft_metrics(pred_new_name,
                                                        gold_new_name)
                example_pred_accs.append(var_metric)
            fun_name = example.ast.compilation_unit
            all_examples[f'{line_num}_{fun_name}'] = \
                (rename_result, Evaluator.average(example_pred_accs))

    return all_examples

seed_stuff()

model = RenamingModel.load(args.model,
                           use_cuda=torch.cuda.is_available(),
                           new_config=extra_config)

decode_results = \
    list(decode(model, examples, model.config).values())
# Get the first function.  There should be only one.
if len(decode_results) == 0:
    raise ValueError("The decoder did not return any variable names.")
else:
    print(json.dumps(decode_results[0]))
