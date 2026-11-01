import sys
import os
import json
import zipfile
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report, ConfusionMatrixDisplay
from wids import make_windows, FEATURES

os.system("")   # turns on colours in the Windows Command Prompt
RED, YEL, GRN, MAG, CYN, BLD, RST = "\033[91m", "\033[93m", "\033[92m", "\033[95m", "\033[96m", "\033[1m", "\033[0m"

ablate = "ablate" in sys.argv
feats = [f for f in FEATURES if not (ablate and f.startswith("deauth"))]
tag = "_ablate" if ablate else ""
print("Features used:", feats)

COLS = ["frame.time_epoch", "wlan.sa", "wlan.ta", "wlan.da", "wlan.ra",
        "wlan.fc.type", "wlan.fc.subtype", "radiotap.dbm_antsignal", "Label"]

# 1. Load only the needed columns from the attack files (21-32)
z = zipfile.ZipFile("AWID3_Dataset_CSV.zip")
parts = []
for i in range(21, 33):
    with z.open(f"CSV/1.Deauth/Deauth_{i}.csv") as f:
        parts.append(pd.read_csv(f, usecols=COLS, low_memory=False))
    print("loaded file", i)
raw = pd.concat(parts, ignore_index=True)

def hexint(v):
    try:
        return int(str(v), 0)
    except Exception:
        return np.nan

def num(s):
    out = pd.to_numeric(s, errors="coerce")
    if out.isna().mean() > 0.5:
        out = s.map(hexint)
    return out

# 2. Convert AWID3 columns to the format wids.py expects
typ = num(raw["wlan.fc.type"])
sub = num(raw["wlan.fc.subtype"])
rssi = pd.to_numeric(raw["radiotap.dbm_antsignal"].astype(str).str.split(",").str[0], errors="coerce")
df = pd.DataFrame({
    "time": pd.to_numeric(raw["frame.time_epoch"], errors="coerce"),
    "src": raw["wlan.sa"].fillna(raw["wlan.ta"]).fillna("unknown"),
    "dst": raw["wlan.da"].fillna(raw["wlan.ra"]).fillna("unknown"),
    "subtype": np.where(typ == 0, sub, -1),   # subtype only counts for management frames
    "rssi": rssi.fillna(-90),
    "label": (raw["Label"] != "Normal").astype(int),
})
df = df.dropna(subset=["time"])
df["src"] = df["src"].astype(str).str.split("-").str[0]
df["dst"] = df["dst"].astype(str).str.split("-").str[0]
print(f"\n{len(df)} frames, {int(df.label.sum())} attack frames")

# 3. Windows + time-based split (train on earlier traffic, test on later traffic)
win = make_windows(df).sort_values("win").reset_index(drop=True)
cut = int(len(win) * 0.7)
tr, te = win.iloc[:cut], win.iloc[cut:].copy()
print(f"{len(win)} windows -> train {len(tr)} (attack {int(tr.label.sum())}), test {len(te)} (attack {int(te.label.sum())})")

# 4. Train + evaluate
clf = RandomForestClassifier(n_estimators=100, random_state=1, class_weight="balanced", n_jobs=-1)
clf.fit(tr[feats], tr.label)
pred = clf.predict(te[feats])
print(f"\nAccuracy: {accuracy_score(te.label, pred):.4f}")
print(classification_report(te.label, pred, target_names=["normal", "attack"], zero_division=0))
cm = confusion_matrix(te.label, pred, labels=[0, 1])
print("Confusion matrix [[TN FP] [FN TP]]:\n", cm)
ConfusionMatrixDisplay(cm, display_labels=["normal", "attack"]).plot(cmap="Blues")
plt.title("AWID3 Deauth - confusion matrix" + (" (no deauth features)" if ablate else ""))
plt.savefig(f"awid_confusion_matrix{tag}.png", dpi=200, bbox_inches="tight")
plt.close()
pd.Series(clf.feature_importances_, index=feats).sort_values().plot.barh(title="AWID3 feature importance")
plt.tight_layout()
plt.savefig(f"awid_feature_importance{tag}.png", dpi=200)
plt.close()

# 5. Coloured alerts + WIPS blocklist
te["pred"] = pred
te["prob"] = clf.predict_proba(te[feats])[:, 1]
ok = te[te.prob < 0.3]
sus = te[(te.prob >= 0.3) & (te.prob < 0.8)]
alr = te[te.prob >= 0.8]
print(f"\n--- WIDS replay of test traffic ---")
print(f"{GRN}OK: {len(ok)} windows{RST}   {YEL}SUSPICIOUS: {len(sus)} windows{RST}   {RED}ALERT: {len(alr)} windows{RST}\n")

shown = pd.concat([ok.head(3), sus.head(5), alr.head(10)]).sort_values("win")
banner = False
for _, r in shown.iterrows():
    info = f"t={int(r.win)} src={r.src} deauth={int(r.deauth_count)} fps={int(r.fps)} p(attack)={r.prob:.2f}"
    if r.prob >= 0.8:
        if not banner:
            print(f"{BLD}{RED}*** ATTACK DETECTED: deauthentication flood ***{RST}")
            banner = True
        print(f"{RED}[ALERT]      {info}{RST}")
    elif r.prob >= 0.3:
        print(f"{YEL}[SUSPICIOUS] {info}{RST}")
    else:
        print(f"{GRN}[OK]         {info}{RST}")

blocked = sorted(m for m in alr.src.unique() if not str(m).lower().startswith("ff:"))
json.dump(blocked, open(f"awid_blocklist{tag}.json", "w"), indent=2)
for m in blocked[:5]:
    print(f"{MAG}[WIPS ] blocking {m} (logged to awid_blocklist{tag}.json){RST}")
print(f"\n{CYN}Saved awid_confusion_matrix{tag}.png and awid_feature_importance{tag}.png{RST}")