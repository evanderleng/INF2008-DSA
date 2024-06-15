import pandas as pd

def process_industry_data(file_path):
    # Load the data
    df = pd.read_excel(file_path, sheet_name='Sheet1')
    # To remove "total" from data as it is only to calculate percentage
    df = df[df['Industry'] != 'Total']
    # Reshape the data for plotting
    data_melted = pd.melt(df, id_vars=['Industry'], value_vars=['2020 %', '2021 %', '2022 %', '2023 %', '2024 %'],
                          var_name='Year', value_name='Percentage')
    # Remove '%' and convert 'Year' to numeric
    data_melted['Year'] = data_melted['Year'].str.replace(' %', '').astype(int)
    # Get the top 3 values of each year
    top_3_per_year = data_melted.groupby('Year').apply(lambda x: x.nlargest(3, 'Percentage')).reset_index(drop=True)
    
    return data_melted, top_3_per_year
