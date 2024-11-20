import csv
import numpy as np
import pandas as pd
import os, sys
import shutil
import time


def progress(count, total, status=''):
    bar_len = 60
    filled_len = int(round(bar_len * count / float(total)))

    percents = round(100.0 * count / float(total), 1)
    bar = "=" * filled_len + "-" * (bar_len - filled_len)

    sys.stdout.write("[%s] %s%%%s\r" % (bar, percents, status))
    sys.stdout.flush()

def main():
  
    repo_list_df = pd.read_csv("repo_list.csv")
    repos_to_be_scanned = repo_list_df["sanitized_repo_name"].tolist()

    absolute_path = os.path.abspath('.')

    error_repos = []
    num_repos = len(repos_to_be_scanned)
    ind = 0
    
    for filename in repos_to_be_scanned:
        progress(ind + 1, num_repos)
        ind = ind + 1

        print("Working with repo:", filename)

        outputDirString = "Reports/" + filename
        isFolderExist = os.path.exists(outputDirString)
        if not isFolderExist:
            os.system("mkdir " + outputDirString)
        else:
            continue     
        
        if filename == '.DS_Store':
            continue
        else:

            try:

                #Code to create repos and move trufflehog True Entropy json files to correct Reports Folder
                
                os.system("trufflehog git --json --regex --entropy --no-update --no-verification  file://Repos/" + filename +  " > " + filename + "_TH_V3_report.json")
                jsonFile = filename + '_TH_V3_report.json'
                os.system("mv " + jsonFile + " " + outputDirString)                

                #Code to run git leaks code on each repo and move gitleaks json file to correct Reports Folder
                os.system("gitleaks detect -v --source=Repos/" + filename + " --report-path=" + filename + "_gitLeaks_report.json")
                jsonFile = filename + '_gitLeaks_report.json'
                os.system("mv " + jsonFile + " " + outputDirString)

            except Exception as e:
                print(e)
                error_repos.append(filename)  
    
    if len(error_repos) > 0:
        error_repos_df = pd.DataFrame(error_repos, columns=["sanitized_repo_name"]) 
        error_repos_df.to_csv("error_repos.csv", index = False)              
            
    return


if __name__ == '__main__':
    main()


