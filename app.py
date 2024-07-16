from flask import *
import plotly.express as px
import plotly.graph_objects as go
import plotly.io as pio
import pandas as pd
import sys
import re

import filteringScript
import importer

import attackvectors
import ransomewareTrend
from industriesTargeted import process_industry_data


app = Flask(__name__)

# update importer
# placed under command due to it requiring a long time to process
if len(sys.argv) > 1:
    if sys.argv[1] == "--run-importer":
        importer.clean_save_dataset("CSV/SIT cve/CVE_Data from NVD database obtained on 08 July 2023.xlsx","CSV/SIT cve/SIT Ransomware CVE List.xlsx")

#Load requried CSVs
filtered_csv = pd.read_csv("CSV/filtered.csv")
data_melted, top_3_per_year = process_industry_data('CSV/attacksByIndustry.xlsx')

#Extract additional specific data from CSVs
ransomware_group_counts, top_groups_by_year = filteringScript.group_extraction(filtered_csv)

#Get plot for ransomware prediction
fig_trend = ransomewareTrend.ransomeware_trend(ransomware_group_counts)


# MAIN PAGE
@app.route('/')
def index():
    return render_template('index.html')

@app.errorhandler(404)
def rdr(e):
    return redirect("/")

# RANSOMWARE GROUPS GRAPHS
@app.route('/ransomwareGroups/')
def ransomwareGroups():
    # Create the Plotly graphs
    fig_all = go.Figure()
    for group in ransomware_group_counts['Ransomware_Group'].unique():
        group_data = ransomware_group_counts[ransomware_group_counts['Ransomware_Group'] == group]
        fig_all.add_trace(go.Scatter(x=group_data['Year'], y=group_data['Frequency'], mode='lines+markers', name=group))
    fig_all.update_layout(title='Ransomware Activity Over the Years', xaxis_title='Year', yaxis_title='Frequency', legend_title='Ransomware Groups')
    graph_html = pio.to_html(fig_all, full_html=False)
    return render_template('groups.html', plot=graph_html)

@app.route('/top3Groups/')
def top3Groups():
    fig_top3 = go.Figure()
    for group in top_groups_by_year['Ransomware_Group'].unique():
        group_data = top_groups_by_year[top_groups_by_year['Ransomware_Group'] == group]
        fig_top3.add_trace(go.Scatter(x=group_data['Year'], y=group_data['Frequency'], mode='lines+markers', name=group))
    fig_top3.update_layout(title='Top 3 Ransomware Groups Activity Per Year', xaxis_title='Year', yaxis_title='Frequency', legend_title='Ransomware Groups')
    graph_html = pio.to_html(fig_top3, full_html=False)
    return render_template('groups.html', plot=graph_html)

# RANSOMWARE FACTORS GRAPHS
@app.route("/Factor/")
def Factorrdr():
    return redirect("/Factor/Vector")

@app.route('/Factor/<string:types>/')
def Factor(types=None):
    accepted_types = ["Vector", "Complexity", "Privilege required", "Top3"]
    if types not in accepted_types or types is None:
        types = "Vector"
    if types == "Top3":
        figure = attackvectors.generate_common_vector_string(filtered_csv)
        graph_html = figure.to_html(full_html=False)
        return render_template('FactorTop3.html', plot=graph_html)

    figure = attackvectors.generate_graph_by_year(filtered_csv, types)
    graph_html = pio.to_html(figure, full_html=False)
    return render_template('groups.html', plot=graph_html)

# RANSOMWARE ATTACKS ON DIFFERENT INDUSTRIES GRAPHS
@app.route('/industriesOverYears/')
def industriesOverYears():
    # Create the Plotly figure
    fig = px.line(data_melted, x='Year', y='Percentage', color='Industry', title='Targeted Industries By Year')
    fig.update_layout(autosize=True)
    # Rename axis data names (remove % sign)
    fig.update_xaxes(tickvals=['2020 %', '2021 %', '2022 %', '2023 %', '2024 %'], ticktext=['2020', '2021', '2022', '2023', '2024'])
    # Convert Plotly figure to HTML
    graph_html = fig.to_html(full_html=False)

    # Render the HTML with the Plotly graph
    return render_template('graphHTML.html', graph_html=graph_html)

@app.route('/top3IndustriesOverYears/')
def top3IndustriesOverYears():
    # Create the Plotly figure
    fig = px.bar(top_3_per_year, x='Year', y='Percentage', color='Industry', title='Top 3 Targeted Industries By Year')
    fig.update_layout(autosize=True, bargap=0.6)
    # Rename axis data names (remove % sign)
    fig.update_xaxes(tickvals=['2020 %', '2021 %', '2022 %', '2023 %', '2024 %'], ticktext=['2020', '2021', '2022', '2023', '2024'])
    # Convert Plotly figure to HTML
    graph_html = fig.to_html(full_html=False)

    # Render the HTML with the Plotly graph
    return render_template('graphHTML.html', graph_html=graph_html)

# GANG AND THEIR CVES AND VECTOR GRAPHS
@app.route('/gang_CVE_association/')
def gang_CVE_association():
    df = filtered_csv.copy()
    df = df.iloc[:, :-2]
    df['Ransomware Group Association'] = df['Ransomware Group Association'].str.split(',', expand=False)
    df = df.explode('Ransomware Group Association')
    year = []    
    for values in df['CVE ID']:
        year.append(re.search(r"""^CVE-(\d{4})-\d{1,}""", values).group(1))
    df['year'] = year
    df_sorted = df.sort_values(by='CVE ID')
    fig = px.scatter(df_sorted, x='CVE ID', y='Ransomware Group Association', color = 'year', width=1920, height=1080,
                     title='Ransomware gang',
                     labels={'Ransomware': 'Ransomware Name'})
    graph_html = fig.to_html(full_html=False)
    return render_template('graphHTML.html', graph_html=graph_html)

@app.route('/gang_vendor_association/')
def gang_vendor_association():
    df = filtered_csv.copy()
    df = df.iloc[:, :-2]
    df['Ransomware Group Association'] = df['Ransomware Group Association'].str.split(',', expand=False)
    df = df.explode('Ransomware Group Association')

    df2 = pd.read_csv('CSV/known_exploited_vulnerabilities.csv')
    df2 = df2.rename(columns={'cveID': 'CVE ID', "vendorProject": 'vendor'})
    df2["vulnerability Info"] = df2[['CVE ID', 'vulnerabilityName']].agg(" ".join, axis=1)

    df3 = df.merge(df2, on='CVE ID', how='inner', suffixes=('_1', '_2'))
    df3 = df3[['Ransomware Group Association', 'vendor', 'vulnerability Info']]

    fig = px.scatter(df3, x='vendor', y='Ransomware Group Association', color="vulnerability Info", width=1920, height=1080,
                     title='Ransomware gangs and their associated vendors and TTP attack vectors')
    graph_html = fig.to_html(full_html=True)
    return render_template('graphHTML.html', graph_html=graph_html)

@app.route('/ransomwareTrend/')
def ransomwareTrend():
    graph_html = pio.to_html(fig_trend, full_html=False)
    return render_template('graphHTML.html', graph_html=graph_html)

if __name__ == '__main__':
    app.run(debug=True)
