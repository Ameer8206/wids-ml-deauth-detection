import sys
import zipfile
import pandas as pd

n = sys.argv[1] if len(sys.argv) > 1 else "0"
member = f"CSV/1.Deauth/Deauth_{n}.csv"
zipfile.ZipFile("AWID3_Dataset_CSV.zip").extract(member, "awid")
path = f"awid/{member}"
print("Extracted:", path)

df = pd.read_csv(path, low_memory=False)
print("Shape (rows, columns):", df.shape)

last = df.columns[-1]
print(f"Last column is '{last}'. Value counts:")
print(df[last].value_counts(dropna=False).head(10))

with open("awid_columns.txt", "w") as f:
    for i, c in enumerate(df.columns):
        f.write(f"{i}\t{c}\n")
print(list(df.columns))
print("Also saved to awid_columns.txt")