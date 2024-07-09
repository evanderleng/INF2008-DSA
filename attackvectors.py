import plotly.graph_objects as go
import pandas as pd


def generate_graph_by_year(df,key_string):
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

def generate_common_vector_string(df):
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