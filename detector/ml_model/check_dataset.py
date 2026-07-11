import pandas as pd

df = pd.read_csv("../datasets/emails.csv")

print("\nColumns:")
print(df.columns)

print("\nFirst 5 Rows:")
print(df.head())

print("\nShape:")
print(df.shape)