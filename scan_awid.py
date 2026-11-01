import zipfile
import pandas as pd

z = zipfile.ZipFile("AWID3_Dataset_CSV.zip")
with open("scan_awid.txt", "w") as out:
    for i in range(33):
        name = f"CSV/1.Deauth/Deauth_{i}.csv"
        with z.open(name) as f:
            counts = pd.read_csv(f, usecols=["Label"])["Label"].value_counts()
        line = f"Deauth_{i}: {dict(counts)}"
        print(line)
        out.write(line + "\n")
print("Done. Saved to scan_awid.txt")