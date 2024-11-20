import json
import csv
import numpy as np
import pandas as pd
import os, sys
import shutil

REPO_DIR = "AssetBench/Repos/"
CODEQL_DATABASE_DIR = "CodeQL/Run Queries/CodeQL_Python_Database/"
OUTPUT_DIR = "CodeQL/Run Queries/CodeQL_Output/"
QUERY_PATH = "CodeQL/detect-asset-codeql/codeql-custom-queries-python/queries/common/"
NO_OF_THREADS = os.cpu_count()


repos = pd.read_csv("repo-list.csv")
repo_name_dict = repos.set_index("sanitized_repo_name")["repo_name"].to_dict()
repo_names = repos["sanitized_repo_name"].tolist()



def runSingleQuery(db_path, query_path, bqrs_out_path, csv_out_path):
    run_cmd = f'codeql query run --warnings=hide --threads={NO_OF_THREADS} --database="{db_path}" --output="{bqrs_out_path}" "{query_path}" > /dev/null'
    os.system(run_cmd)
    
    decode_cmd = f'codeql bqrs decode --format=csv --output="{csv_out_path}" "{bqrs_out_path}" > /dev/null'
    os.system(decode_cmd)
    
def runQueries(repo_name):
    for filename in os.listdir(QUERY_PATH):
        query_name = filename.strip(".ql")
        out_dir_path = OUTPUT_DIR + repo_name
        if not os.path.exists(out_dir_path):
            os.mkdir(out_dir_path)
        
        csv_out_path = os.path.join(out_dir_path, repo_name + "-" + query_name + ".csv")
        bqrs_out_path = os.path.join(out_dir_path, repo_name + "-" + query_name + ".bqrs")
            
        runSingleQuery(CODEQL_DATABASE_DIR + repo_name, QUERY_PATH + filename, bqrs_out_path, csv_out_path)  
        
    

def createDatabase(repo_name):
    if not os.path.exists(CODEQL_DATABASE_DIR + repo_name):
        db_create_cmd = f'codeql database create "{CODEQL_DATABASE_DIR + repo_name}" --source-root "{REPO_DIR + repo_name}" --language=python --threads={NO_OF_THREADS} > /dev/null'
        os.system(db_create_cmd)



for idx, repo_name in enumerate(repo_names):
    print(f"Working with repo: {repo_name} - ({str(idx + 1)}/{len(repo_names)})")
    print("Creating python database...")
    createDatabase(repo_name)
    print("Running codeql queries...")
    runQueries(repo_name)
    print(f"Done with repo: {repo_name}")