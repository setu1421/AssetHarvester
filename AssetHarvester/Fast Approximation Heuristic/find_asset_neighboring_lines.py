import json
import csv
import numpy as np
import pandas as pd
import os, sys
import shutil
import re
from tqdm import tqdm
from pandarallel import pandarallel
from urllib.parse import urlparse, parse_qs
import string
from difflib import SequenceMatcher
import jellyfish
from git import Repo
import linecache
import heapq


FILE_DIR = "AssetBench/Files"
IP_REGEX = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
DNS_REGEX = r"\b[A-Za-z0-9][A-Za-z0-9-.]*\.\D{2,4}\b"

def isAssetPresent(line):
    match = re.search(IP_REGEX, line)
    if not match:
        match = re.search(DNS_REGEX, line)
    
    if match:
        asset_value = line[match.start():match.end()]
        return (TRUE, asset_value) 
    
    return (False, None)
    

def find_one_asset(file_identifier, secret_line):
    heap = []

    base_line = linecache.getline(os.path.join(FILE_DIR, file_identifier), int(start_line))
    base_line_no = start_line
    
    for line_no in range(base_line_no - 3, base_line_no + 4): 
        asset_line = linecache.getline(os.path.join(FILE_DIR, file_identifier), line_no)
        is_asset, asset_value = isAssetPresent(asset_line)
        if is_asset:  
            similarity_score = jellyfish.jaro_similarity(base_line, asset_line)
            if similarity_score < 0.5:
                continue
            diff = abs(base_line_no - line_no)
            heapq.heappush(heap, (diff, -similarity_score, line_no, asset_value))
    
    return (heap[0][2], heap[0][3])



# filter the secret-asset pairs where secret-asset present in same file and file_identifier is present
# and not being found by previous rules
data_df = pd.read_csv("secrets.csv")
already_found_assets = pd.read_csv("secret_asset_found.csv")
filtered_data_df = data_df[(data_df["in_same_file"] == 'Y') & 
                                     ~(data_df["file_identifier"].isnull())]
already_found_asset_row_ids = already_found_assets["id"].tolist()

assets_with_range_line = []


for index, row in filtered_data_df.iterrows():
    # if commit id is not present.
    if row["id"] in already_found_asset_row_ids:
        continue
  
    asset_line, found_asset = find_one_asset(row["file_identifier"], row["start_line"])
    curr = {"id": row["id"],
            "secret": row["secret"],
            "db_type": row["db_type"],
            "secret_label": row["secret_label"],
            "repo_name": row["repo_name"],
            "repo_identifier": row["repo_identifier"],
            "commit_id": row["commit_id"],
            "file_path": row["file_path"],
            "start_line": row["start_line"],
            "asset_value": found_asset,
            "asset_line_no": asset_line}
    assets_with_range_line.append(curr) 
        
assets_with_range_line_df = pd.DataFrame(assets_with_range_line)      
assets_with_range_line_df.to_csv("assets_with_range_line.csv", index = False)  