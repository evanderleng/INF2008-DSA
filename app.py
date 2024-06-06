from flask import Flask, render_template, request
import pandas as pd
import plotly.graph_objects as go
import plotly.io as pio

# Load the data
ransomware_group_counts = pd.read_csv('filteredRansomwareData.csv')
top_groups_by_year = pd.read_csv('topThreeGroupsPerYear.csv')

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

# Flask app to serve the plots
app = Flask(__name__)

@app.route('/')
def plot_all():
    graph_html = pio.to_html(fig_all, full_html=False)
    return render_template("graph.html", plot=graph_html)

@app.route('/top3')
def plot_top3():
    graph_html = pio.to_html(fig_top3, full_html=False)
    return render_template("graph.html", plot=graph_html)

if __name__ == '__main__':
    app.run(debug=True)
