import json
import csv
import numpy as np
import pandas as pd
import os, sys
import shutil
import re
import jellyfish
import heapq
import yaml
import xmltodict
import json


CODEQL_OUTPUT_DIR = 'CodeQL/Run Queries/CodeQL_Output'
repo_list_df = pd.read_csv("repo-list.csv")
repo_name_dict = repo_list_df.set_index('sanitized_repo_name')["repo_name"].to_dict()


# Merge the AssetsInParameter and KeywordArgument results 
def sanitizeLocationName(locationName, sanitized_repo_name):
    if locationName != "Not Found":
        return locationName.split(sanitized_repo_name + '/')[1]
    else:
        return locationName
    
def sanitizeEmptyRows(hostValue, dbValue, userValue, passwordValue):
    hostValue = str(hostValue).strip()
    dbValue = str(dbValue).strip()
    userValue = str(userValue).strip()
    passwordValue = str(passwordValue).strip()
    
    return ((hostValue == "Not Found" or hostValue == "''") and (dbValue == "Not Found" or dbValue == "''")
       and (userValue == "Not Found" or userValue == "''") and 
      (passwordValue == "Not Found" or passwordValue == "''")) 


final_df = pd.DataFrame(columns =['callLocation', 'hostValue', 'hostLocation', 'portValue',
                                  'portLocation', 'dbValue', 'dbLocation', 'userValue', 'userLocation', 
                                  'passwordValue', 'passwordLocation', 'dbType'])

for foldername in os.listdir(CODEQL_OUTPUT_DIR):
    assets_in_parameter_path = os.path.join(CODEQL_OUTPUT_DIR, foldername, foldername + "-AssetsInParameter.csv")
    keywords_arguments_path = os.path.join(CODEQL_OUTPUT_DIR, foldername, foldername + "-KeywordArguments.csv")
    if os.path.exists(assets_in_parameter_path):
        assets_in_parameter_df = pd.read_csv(assets_in_parameter_path)
        # add the repository name
        assets_in_parameter_df["sanitized_repo_name"] = foldername 
        assets_in_parameter_df["repo_name"] = repo_name_dict[foldername]
        final_df = pd.concat([final_df, assets_in_parameter_df], ignore_index = True)
    if os.path.exists(keywords_arguments_path):    
        keywords_arguments_df = pd.read_csv(keywords_arguments_path)
        # add the repository name
        keywords_arguments_df["sanitized_repo_name"] = foldername
        keywords_arguments_df["repo_name"] = repo_name_dict[foldername]
        final_df = pd.concat([final_df, keywords_arguments_df], ignore_index = True)
    
# Remove computer location from the locations
final_df["callLocation"] = final_df[["callLocation", "sanitized_repo_name"]].apply(lambda x: 
                            sanitizeLocationName(x.callLocation, x.sanitized_repo_name), axis = 1)
final_df["hostLocation"] = final_df[["hostLocation", "sanitized_repo_name"]].apply(lambda x: 
                            sanitizeLocationName(x.hostLocation, x.sanitized_repo_name), axis = 1)
final_df["portLocation"] = final_df[["portLocation", "sanitized_repo_name"]].apply(lambda x: 
                            sanitizeLocationName(x.portLocation, x.sanitized_repo_name), axis = 1)
final_df["dbLocation"] = final_df[["dbLocation", "sanitized_repo_name"]].apply(lambda x: 
                            sanitizeLocationName(x.dbLocation, x.sanitized_repo_name), axis = 1)
final_df["userLocation"] = final_df[["userLocation", "sanitized_repo_name"]].apply(lambda x: 
                            sanitizeLocationName(x.userLocation, x.sanitized_repo_name), axis = 1)
final_df["passwordLocation"] = final_df[["passwordLocation", "sanitized_repo_name"]].apply(lambda x: 
                            sanitizeLocationName(x.passwordLocation, x.sanitized_repo_name), axis = 1)


# Remove empty entries which are all "Not Found"
final_df["isEmpty"] = final_df[["hostValue", "dbValue", "userValue", "passwordValue"]].apply(lambda x: 
                              sanitizeEmptyRows(x.hostValue, x.dbValue, x.userValue, x.passwordValue), axis = 1)
final_df = final_df[final_df["isEmpty"] == False]
final_df.drop('isEmpty', axis=1, inplace=True)

# Remove duplicate entries
final_df = final_df.drop_duplicates(subset=['callLocation', 'hostValue', 'hostLocation', 
                                 'portValue', 'portLocation', 'dbValue', 'dbLocation', 
                                 'userValue', 'userLocation', 'passwordValue',
                                 'passwordLocation', 'repo_name'], 
                             keep="first").reset_index(drop = True)


final_df.to_csv("Results/assets_with_parameter_and_keyword_arguments.csv", index = False)


# Retrieve DSN-URI results
def sanitizeDSNRows(dsnValue):
    dsnValue = str(dsnValue).strip(' "\'\t\r\n')
    
    return ((dsnValue == "Not Found" or len(dsnValue) <= 3 or dsnValue in ['',':',"@","/", "?",  "&"]) 
           or dsnValue.startswith(("?", "=", "&", ";", ":", "{", "/", "%s", ".")))

final_df = pd.DataFrame(columns =['callLocation', 'dsn', 'dsnLocation', 'dsnStartColumn', 'dbType'])

for foldername in os.listdir(CODEQL_OUTPUT_DIR):
    dsn_uri_path = os.path.join(CODEQL_OUTPUT_DIR, foldername, foldername + "-DSN-URI.csv")
    if os.path.exists(dsn_uri_path):
        dsn_uri_df = pd.read_csv(dsn_uri_path)
        # add the repository name
        dsn_uri_df["sanitized_repo_name"] = foldername 
        dsn_uri_df["repo_name"] = repo_name_dict[foldername]
        # Filter out the anaconda entries
        dsn_uri_df = dsn_uri_df[~(dsn_uri_df["callLocation"].str.contains("opt/anaconda3") |
                                  dsn_uri_df["dsnLocation"].str.contains("opt/anaconda3"))]
        final_df = pd.concat([final_df, dsn_uri_df], ignore_index = True)
        
# Remove computer location from the locations
final_df["callLocation"] = final_df[["callLocation", "sanitized_repo_name"]].apply(lambda x: 
                            sanitizeLocationName(x.callLocation, x.sanitized_repo_name), axis = 1)
final_df["dsnLocation"] = final_df[["dsnLocation", "sanitized_repo_name"]].apply(lambda x: 
                            sanitizeLocationName(x.dsnLocation, x.sanitized_repo_name), axis = 1)

# Remove empty entries which are all "Not Found"
final_df["isEmpty"] = final_df[["dsn"]].apply(lambda x: 
                              sanitizeDSNRows(x.dsn), axis = 1)
final_df = final_df[final_df["isEmpty"] == False]
final_df.drop('isEmpty', axis=1, inplace=True)

# Remove duplicate entries
final_df = final_df.drop_duplicates(subset=['callLocation', 'dsn', 'dsnLocation', 'dsnStartColumn', 'repo_name'], 
                             keep="first").reset_index(drop = True)


final_df.to_csv("Results/assets_in_dsn.csv", index = False) 

# Merge Config File Assets (Non .py files)
def sanitizeEmptyRowsConfigFile(fileName, hostKey, portKey, dbKey, userKey, passwordKey):
    fileName = str(fileName).strip()
    hostKey = str(hostKey).strip()
    portKey = str(portKey).strip()
    dbKey = str(dbKey).strip()
    userKey = str(userKey).strip()
    passwordKey = str(passwordKey).strip()
    
    return ((fileName == "Not Found" or fileName == "''") and (hostKey == "Not Found" or hostKey == "''")
       and (portKey == "Not Found" or portKey == "''") and 
      (dbKey == "Not Found" or dbKey == "''") and (userKey == "Not Found" or userKey == "''") and 
      (passwordKey == "Not Found" or passwordKey == "''"))  

final_df = pd.DataFrame(columns =['callLocation', 'fileName', 'hostKey', 'portKey',
                                  'dbKey', 'userKey', 'passwordKey', 'dbType'])

for foldername in os.listdir(CODEQL_OUTPUT_DIR):
    config_file_path = os.path.join(CODEQL_OUTPUT_DIR, foldername, foldername + "-ConfigFile.csv")
    if os.path.exists(config_file_path):
        config_file_df = pd.read_csv(config_file_path)
        # add the repository name
        config_file_df["sanitized_repo_name"] = foldername 
        config_file_df["repo_name"] = repo_name_dict[foldername]
        final_df = pd.concat([final_df, config_file_df], ignore_index = True)     
    
# Remove computer location from the locations
final_df["callLocation"] = final_df[["callLocation", "sanitized_repo_name"]].apply(lambda x: 
                            sanitizeLocationName(x.callLocation, x.sanitized_repo_name), axis = 1)


# Remove empty entries which are all "Not Found"
final_df["isEmpty"] = final_df[["fileName", "hostKey", "portKey", "dbKey", 
                                "userKey", "passwordKey"]].apply(lambda x: 
                              sanitizeEmptyRowsConfigFile(x.fileName, x.hostKey, x.portKey, 
                                                x.dbKey, x.userKey, x.passwordKey), axis = 1)
final_df = final_df[final_df["isEmpty"] == False]
final_df.drop('isEmpty', axis=1, inplace=True)

# Remove duplicate entries
final_df = final_df.drop_duplicates(subset=['callLocation', 'fileName', 'hostKey', 
                                 'portKey', 'dbKey', 'userKey', 'passwordKey', 'repo_name'], 
                             keep="first").reset_index(drop = True)


final_df.to_csv("Results/assets_in_config_file.csv", index = False)


# Check jarowinkler distance
def jaro_similar(a, b):
    a = a.lower()
    b = b.lower()
    
    match_ratio = jellyfish.jaro_similarity(a, b)
    return match_ratio

def findRelevantFiles(callLocation, configFile, sanitized_repo_name):
    rel_files = []
    callLocationPath = os.path.join(REPO_DIR, sanitized_repo_name, callLocation)

    for root, dirs, files in os.walk(os.path.join(REPO_DIR, sanitized_repo_name)):
        for file in files:
            if file.endswith(configFile):
                match_file_path = os.path.join(root, file) 
                file_similarity_score = jaro_similar(match_file_path, callLocationPath)
                heapq.heappush(rel_files, (-file_similarity_score, match_file_path))
                
    return rel_files  

def getKeyValueLocation(file_path, key, value):
    with open(file_path, 'r') as f:
        for i, line in enumerate(f):
            if str(key) in line and str(value) in line:
                return i + 1
    
    return -1
   

def parseYAMLFile(f):
    return yaml.safe_load(f)

def parseXMLFile(f):
    return xmltodict.parse(f)

def parseJSONFile(f):
    return json.load(f)


def getFileType(file_name):
    if ".yml" in file_name or ".yaml" in file_name:
        return "YAML"
    
    if ".xml" in file_name:
        return "XML"
    
    if ".js" in file_nme or ".json" in file_name:
        return "JSON"
    
    return None
    
    
# Parse the config file to get the key value pairs
def parseFile(row, file_type):
    callLocation = row["callLocation"]
    configFile = row["fileName"]
    sanitizedRepoName = row["sanitized_repo_name"]
    
    # Find the relevant files since multiple files with same name can be present
    rel_files = findRelevantFiles(callLocation, configFile, sanitizedRepoName)
    curr_res = {"callLocation": callLocation}
    
    while rel_files:
        # choose the most relevant file based on jaro-winkler similarity
        _,curr_file = rel_files.pop()
        with open(curr_file, 'r') as f:
            data_mp = None
            if file_type == "YAML":
                data_mp = parseYAMLFile(f)
            elif file_type == "XML":
                data_mp = parseXMLFile(f)
            elif file_type == "JSON":
                data_mp = parseJSONFile(f)
    
                
            if row["hostKey"] in data_mp:
                curr_res["hostValue"] = data_mp[row["hostKey"]]
                line_no = getKeyValueLocation(f.name, row["hostKey"], curr_res["hostValue"])
                curr_res["hostLocation"] = f.name.split(sanitizedRepoName + "/")[1] + ":" + str(line_no)
            if row["portKey"] in data_mp:
                curr_res["portValue"] = data_mp[row["portKey"]]
                line_no = getKeyValueLocation(f.name, row["portKey"], curr_res["portValue"])
                curr_res["portLocation"] = f.name.split(sanitizedRepoName + "/")[1] + ":" + str(line_no)
            if row["dbKey"] in data_mp:
                curr_res["dbValue"] = data_mp[row["dbKey"]]
                line_no = getKeyValueLocation(f.name, row["dbKey"], curr_res["dbValue"])
                curr_res["dbLocation"] = f.name.split(sanitizedRepoName + "/")[1] + ":" + str(line_no)
            if row["userKey"] in data_mp:
                curr_res["userValue"] = data_mp[row["userKey"]]
                line_no = getKeyValueLocation(f.name, row["userKey"], curr_res["userValue"])
                curr_res["userLocation"] = f.name.split(sanitizedRepoName + "/")[1] + ":" + str(line_no)
            if row["passwordKey"] in data_mp:
                curr_res["passwordValue"] = data_mp[row["passwordKey"]]   
                line_no = getKeyValueLocation(f.name, row["passwordKey"], curr_res["passwordValue"])
                curr_res["passwordLocation"] = f.name.split(sanitizedRepoName + "/")[1] + ":" + str(line_no)
        
        if len(curr_res) > 0:
            curr_res["dbType"] = row["dbType"]
            curr_res["sanitized_repo_name"] = sanitizedRepoName
            curr_res["repo_name"] = row["repo_name"]
            return curr_res
    
    return None

REPO_DIR = "AssetBench/Repos"
config_df = pd.read_csv("Results/assets_in_config_file.csv")

final_res = []

for index, row in config_df.iterrows():
    file_type = getFileType(row["fileName"]) 
    if not file_type:
        continue
        
    curr_res = parseFile(row, file_type)
    if curr_res:
        final_res.append(curr_res)          

if final_res:
    final_res_df = pd.DataFrame(final_res)
    final_res_df.to_csv("Results/assets_in_config_file_final.csv", index = False) 