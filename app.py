from flask import * 
import plotly.express as px
import plotly.graph_objects as go
import plotly.io as pio
import pandas as pd

from attackvectors import Vectors
from industriesTargeted import process_industry_data

app = Flask(__name__) 

# GET RANSOMWARE GROUPS
ransomware_group_counts = pd.read_csv('filteredRansomwareData.csv')
top_groups_by_year = pd.read_csv('topThreeGroupsPerYear.csv')

# GET RANSOMWARE VECTORS
vector_filtered = pd.read_csv("vectorfiltered.csv")
vector_class = Vectors()

# GET RANSOMWARE TARGETED INDUSTRIES
data_melted, top_3_per_year = process_industry_data('attacksByIndustry.xlsx')

# Create the Plotly graphs
fig_all = go.Figure()
for group in ransomware_group_counts['Ransomware_Group'].unique():
    group_data = ransomware_group_counts[ransomware_group_counts['Ransomware_Group'] == group]
    fig_all.add_trace(go.Scatter(x=group_data['Year'], y=group_data['Frequency'], mode='lines+markers', name=group))
fig_all.update_layout(title='Ransomware Activity Over the Years', xaxis_title='Year', yaxis_title='Frequency', legend_title='Ransomware Groups')

fig_top3 = go.Figure()
for group in top_groups_by_year['Ransomware_Group'].unique():
    group_data = top_groups_by_year[top_groups_by_year['Ransomware_Group'] == group]
    fig_top3.add_trace(go.Scatter(x=group_data['Year'], y=group_data['Frequency'], mode='lines+markers', name=group))
fig_top3.update_layout(title='Top 3 Ransomware Groups Activity Per Year', xaxis_title='Year', yaxis_title='Frequency', legend_title='Ransomware Groups')


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
    graph_html = pio.to_html(fig_all, full_html=False)
    return render_template('groups.html', plot=graph_html)

@app.route('/top3Groups/')
def top3Groups():
    graph_html = pio.to_html(fig_top3, full_html=False)
    return render_template('groups.html', plot=graph_html)

# RANSOMWARE FACTORS GRAPHS
@app.route("/Factor/")
def Factorrdr():
    return redirect("/Factor/Vector")

@app.route('/Factor/<string:types>/')
def Factor(types=None):
    accepted_types = ["Vector","Complexity","Privilege required","Top3"]
    if types not in accepted_types or types is None:
        types = "Vector"
    if types == "Top3":
        figure = vector_class.generate_common_vector_string(vector_filtered)
        graph_html = figure.to_html(full_html=False)
        return render_template('FactorTop3.html', plot=graph_html)
    
    figure = vector_class.generate_graph_by_year(vector_filtered,types)
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
    df = pd.read_csv('./ransomware_csv.csv')
    df = df.iloc[:,:-2]
    df['Ransomware Group Association'] = df['Ransomware Group Association'].str.split(',', expand=False)
    df = df.explode('Ransomware Group Association')
    
    df_sorted = df.sort_values(by='CVE ID')
    fig = px.scatter(df_sorted, x='CVE ID', y='Ransomware Group Association', width=1920, height = 1080,
             title='Ransomware gang',
             labels={'Ransomware': 'Ransomware Name'})
    graph_html = fig.to_html(full_html=False)
    return render_template('graphHTML.html', graph_html=graph_html)

@app.route('/gang_vendor_association/')
def gang_vendor_association():
    df = pd.read_csv('./ransomware_csv.csv')
    df = df.iloc[:,:-2]
    df['Ransomware Group Association'] = df['Ransomware Group Association'].str.split(',', expand=False)
    df = df.explode('Ransomware Group Association')
    
    df2 = pd.read_csv('./known_exploited_vulnerabilities.csv')
    df2 = df2.rename(columns={'cveID': 'CVE ID', "vendorProject": 'vendor'})
    df2["vulnerability Info"] = df2[['CVE ID', 'vulnerabilityName']].agg(" ".join, axis=1)
    
    df3 = df.merge(df2, on='CVE ID', how='inner', suffixes=('_1', '_2'))
    df3 = df3[['Ransomware Group Association', 'vendor','vulnerability Info']]
    
    fig = px.scatter(df3, x='vendor',  y='Ransomware Group Association', color="vulnerability Info", width=1920, height = 1080,
             title='Ransomware gangs and their associated vendors and TTP attack vectors')
    graph_html = fig.to_html(full_html=True)
    return render_template('graphHTML.html', graph_html=graph_html)


if __name__ == '__main__': 
	app.run(debug=True)
