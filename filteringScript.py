import pandas as pd

def group_extraction(ransomware_data):
    # Load the data
    # ransomware_data = pd.read_csv('CSV/ransomware_csv.csv')
    ransomware_data = ransomware_data[['CVE ID', 'Ransomware Group Association']]

    # Extract the year from the CVE ID
    ransomware_data['Year'] = ransomware_data['CVE ID'].apply(lambda x: x.split('-')[1])
    ransomware_data['Year']=ransomware_data['Year'].astype(int)

    # Expand the Ransomware Group Association into individual rows
    ransomware_data_expanded = ransomware_data['Ransomware Group Association'].str.split(', ').explode().to_frame(name='Ransomware_Group')

    # Join the expanded ransomware groups back with the years
    ransomware_data_filtered = ransomware_data[['Year']].join(ransomware_data_expanded.reset_index(drop=True))

    # Group by year and ransomware group to count occurrences
    ransomware_group_counts = ransomware_data_filtered.groupby(['Year', 'Ransomware_Group']).size().reset_index(name='Frequency')

    # Save to a new file
    # ransomware_group_counts.to_csv('CSV/filteredRansomwareData.csv', index=False)

    # Determine the top 3 groups for each year
    top_groups_by_year = ransomware_group_counts.groupby('Year').apply(
        lambda x: x.nlargest(3, 'Frequency')
    ).reset_index(drop=True)

    # Save the top 3 groups data to another file
    # top_groups_by_year.to_csv('CSV/topThreeGroupsPerYear.csv', index=False)

    return ransomware_group_counts, top_groups_by_year
