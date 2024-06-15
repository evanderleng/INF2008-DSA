import plotly.graph_objects as go
import pandas as pd


class Vectors:
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

    def filter_df_data(self,main,sit):
        # filter data base on required fields and use only cve found in SIT randsomware list
        main = main[['CVE ID', 'Vector String','Base Severity']]
        result_df = sit.merge(main,on="CVE ID", how="left")
        # create year column
        result_df['Year'] = result_df["CVE ID"].str.extract(r'CVE-(\d{4})-\d{4}')
        # remove CVE without vector strings to clean up data
        result_df = result_df.dropna(subset=["Vector String"])
        result_df = result_df.reset_index(drop=True)
        # create readable columns of important CVSS vector string data
        new_columns = result_df.apply(self.parse_vector_string, axis=1, result_type='expand')
        result_df = pd.concat([result_df, new_columns], axis=1)

        # print(result_df)
        return result_df


    
    def parse_vector_string(self, df):
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
        vec_dict["Vector"] = self.mapping[temp[0]][temp[1]]
        temp = components[1].split(":")
        vec_dict["Complexity"] = self.mapping[temp[0]][temp[1]]
        temp = components[2].split(":")
        vec_dict["Privilege required"] = self.mapping[temp[0]][temp[1]]

        return vec_dict
    
    def generate_graph_by_year(self,df,key_string):
        # generates plotly graph based on selected keys
        # only allows vector, complexity, and privilege required
        df1 = df[['CVE ID','Base Severity','Year','Vector','Complexity','Privilege required']]
        # group by year and keystring only. get total number of each unique value in key_string column, grouped by year
        df1 = df1.groupby(['Year', key_string]).size().reset_index(name='Frequency')
        
        # create plotly figure based on data
        fig_all = go.Figure()
        for vector in df1[key_string].unique():
            vector_data = df1[df1[key_string] == vector]
            fig_all.add_trace(go.Scatter(x=vector_data['Year'], y=vector_data['Frequency'], mode='lines+markers', name=vector))
        fig_all.update_layout(title='{} by Year'.format(key_string), xaxis_title='Year', yaxis_title='Frequency', legend_title=key_string)
        return fig_all
    
    def generate_common_vector_string(self,df):
        df1 = df[['Year','Vector','Complexity','Privilege required']]

        # sorts each combination of vector, complexity, and privilege and counts each unique combination. sorts by year
        unique_combinations = df1.groupby(['Year','Vector','Complexity','Privilege required']).size().reset_index(name='Frequency')
        
        # keep only top 3 unique combinations
        top_3_combi = unique_combinations.groupby('Year').apply(lambda x: x.nlargest(3, 'Frequency')).reset_index(drop=True)
        # print(top_3_combi)

        # create table figure based on top 3 data
        fig = go.Figure()
        fig.add_trace(go.Table(
            header=dict(values=['Year','Vector','Complexity','Privilege required','Frequency'],
                        fill_color='paleturquoise',
                        align='left'),
            cells=dict(values=[top_3_combi["Year"], top_3_combi["Vector"], top_3_combi["Complexity"], top_3_combi["Privilege required"],top_3_combi["Frequency"]],
                    fill_color='lavender',
                    align='left')))
        fig.update_layout(title='Top 3 Attack Vector Combination used by year')
        return fig



if __name__ == "__main__":
    # Generate attack vector specific csv data
    vectors = Vectors()
    mainCVE = pd.read_excel('SIT cve\CVE_Data from NVD database obtained on 08 July 2023.xlsx', sheet_name='Sheet1')
    sitRansomwareCVE = pd.read_excel('SIT cve\SIT Ransomware CVE List.xlsx', sheet_name='Sheet1')
    filtered_df = vectors.filter_df_data(mainCVE,sitRansomwareCVE)
    filtered_df.to_csv("vectorfiltered.csv")