import plotly.graph_objects as go
from sklearn.linear_model import LinearRegression
import numpy as np


def ransomeware_trend(ransomware_group_counts):
    # Calculate the total number of ransomware attacks for each year
    total_attacks_per_year = ransomware_group_counts.groupby('Year')['Frequency'].sum().reset_index()
    total_attacks_per_year.columns = ['Year', 'Total_Attacks']

    # Separate the data before and after 2023
    before_2023 = total_attacks_per_year[total_attacks_per_year['Year'] < 2023]
    after_2023 = total_attacks_per_year[total_attacks_per_year['Year'] >= 2023]

    # Calculate average attacks before and after 2023
    avg_attacks_before_2023 = before_2023['Total_Attacks'].mean()
    avg_attacks_after_2023 = after_2023['Total_Attacks'].mean()

    # Fit a linear regression model for prediction
    X = total_attacks_per_year[['Year']]
    y = total_attacks_per_year['Total_Attacks']
    model = LinearRegression()
    model.fit(X, y)

    # Predict future attacks for the next 5 years
    future_years = np.arange(2024, 2029).reshape(-1, 1)
    predicted_attacks = model.predict(future_years)

    # Create a plotly graph to show the trend and prediction
    fig_trend = go.Figure()
    fig_trend.add_trace(go.Scatter(x=total_attacks_per_year['Year'], y=total_attacks_per_year['Total_Attacks'], mode='lines+markers', name='Total Attacks'))
    fig_trend.add_trace(go.Scatter(x=[2022], y=[avg_attacks_before_2023], mode='markers', name='Avg Attacks Before 2023', marker=dict(color='red', size=10)))
    fig_trend.add_trace(go.Scatter(x=[2023], y=[avg_attacks_after_2023], mode='markers', name='Avg Attacks After 2023', marker=dict(color='green', size=10)))
    fig_trend.add_trace(go.Scatter(x=future_years.flatten(), y=predicted_attacks, mode='lines+markers', name='Predicted Trend', line=dict(color='blue', dash='dot')))
    fig_trend.update_layout(title='Ransomware Attacks Trend', xaxis_title='Year', yaxis_title='Total Attacks', legend_title='Legend')
    
    return fig_trend
