import pandas as pd

# Load dataset
df = pd.read_csv("network_features.csv")

print("Original rows:", len(df))

# Remove rows with missing values
df = df.dropna()

# Convert protocol into numerical values
df = pd.get_dummies(df, columns=["protocol"])

# Save prepared dataset
df.to_csv("prepared_features.csv", index=False)

print("Prepared rows:", len(df))
print("\nFeatures:")
print(df.columns.tolist())

print("\nDataset saved as prepared_features.csv")