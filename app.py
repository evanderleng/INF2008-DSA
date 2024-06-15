from flask import * 
import plotly.express as px
import plotly.graph_objects as go
import plotly.io as pio
import pandas as pd

from attackvectors import Vectors

app = Flask(__name__) 

# GET RANSOMWARE GROUPS
# Load the data
ransomware_group_counts = pd.read_csv('filteredRansomwareData.csv')
top_groups_by_year = pd.read_csv('topThreeGroupsPerYear.csv')

vector_filtered = pd.read_csv("vectorfiltered.csv")
vector_class = Vectors()



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


# GET RANSOMWARE ATTTACK BY INDUSTRIES
# Load the data
df = pd.read_excel('attacksByIndustry.xlsx', sheet_name='Sheet1')
# To remove "total" from data as it is only to calculate percentage
df = df[df['Industry'] != 'Total']
# Reshape the data for plotting
data_melted = pd.melt(df, id_vars=['Industry'], value_vars=['2020 %', '2021 %', '2022 %', '2023 %', '2024 %'],
var_name='Year', value_name='Percentage')
# Reshape the data for plotting
data_melted = pd.melt(df, id_vars=['Industry'], value_vars=['2020 %', '2021 %', '2022 %', '2023 %', '2024 %'],
var_name='Year', value_name='Percentage')
# Remove '%' and convert 'Year' to numeric
data_melted['Year'] = data_melted['Year'].str.replace(' %', '').astype(int)
# Get the top 3 values of each year
top_3_per_year = data_melted.groupby('Year').apply(lambda x: x.nlargest(3, 'Percentage')).reset_index(drop=True)

# MAIN PAGE
@app.route('/') 
def index(): 
	return render_template('index.html') 
@app.errorhandler(404)
def rdr(e):
    return redirect("/")

# RANSOMWARE GROUPS BY NUMBER OF ATTACKS GRAPHS
@app.route('/ransomwareGroups/')
def ransomwareGroups():
    graph_html = pio.to_html(fig_all, full_html=False)
    return render_template('groups.html', plot=graph_html)

@app.route('/top3Groups/')
def top3Groups():
    graph_html = pio.to_html(fig_top3, full_html=False)
    return render_template('groups.html', plot=graph_html)

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
    return render_template('industries.html', graph_html=graph_html)

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
    return render_template('industries.html', graph_html=graph_html)



if __name__ == '__main__': 
	app.run(debug=True)
