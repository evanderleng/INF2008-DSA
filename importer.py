import pandas as pd

# mappings to map CVSS vector string into something more readable
# combined ver 2.0 and 3.0 specifications into one.
mapping={
    "AV":{
        "L":"Local",
        "A":"Ajacent network",
        "N":"Network",
        "P":"Local"
    },
    "AC":{
        "L":"Low",
        "M":"Medium",
        "H":"High"
    },
    "Au":{
        "N":"Low",
        "S":"Medium",
        "M":"High"
    },
    "PR":{
        "N":"Low",
        "L":"Medium",
        "H":"High"
    }
}

def filter_df_data(main,sit):
    # filter data base on required fields and use only cve found in SIT randsomware list
    main = main[['CVE ID', 'Vector String','Base Severity']]
    result_df = sit.merge(main,on="CVE ID", how="left")
    # create year column
    result_df['Year'] = result_df["CVE ID"].str.extract(r'CVE-(\d{4})-\d{4}')
    # remove CVE without vector strings to clean up data
    result_df = result_df.dropna(subset=["Vector String"])
    result_df = result_df.reset_index(drop=True)
    # create readable columns of important CVSS vector string data
    new_columns = result_df.apply(parse_vector_string, axis=1, result_type='expand')
    result_df = pd.concat([result_df, new_columns], axis=1)

    # print(result_df)
    return result_df

def parse_vector_string(df):
    # convert CVE vector string in to something readable.
    # also filter out based on useful components
    vec_dict = {"Vector":"",
        "Complexity":"",
        "Privilege required":""}
    
    # Split CVSS string into its sub components
    components=df["Vector String"].split("/")
    # remove CVSS ver 3 identifier
    if components[0] == "CVSS:3.1" or components[0] == "CVSS:3.0":
        components.pop(0)
    # assign each vec_dict key based on mappings
    temp = components[0].split(":")
    vec_dict["Vector"] = mapping[temp[0]][temp[1]]
    temp = components[1].split(":")
    vec_dict["Complexity"] = mapping[temp[0]][temp[1]]
    temp = components[2].split(":")
    vec_dict["Privilege required"] = mapping[temp[0]][temp[1]]

    return vec_dict

def clean_save_dataset(main_CVE_loc="CSV/SIT cve/CVE_Data from NVD database obtained on 08 July 2023.xlsx", sit_cve_loc="CSV/SIT cve/SIT Ransomware CVE List.xlsx"):
    mainCVE = pd.read_excel(main_CVE_loc, sheet_name='Sheet1')
    sitRansomwareCVE = pd.read_excel(sit_cve_loc, sheet_name='Sheet1')
    filtered_df = filter_df_data(mainCVE,sitRansomwareCVE)
    filtered_df.to_csv("CSV/filtered.csv")