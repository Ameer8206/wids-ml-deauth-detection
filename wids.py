#!/usr/bin/env python3
"""
Basic ML-based WIDS/WIPS: detects deauthentication flood attacks.

Pipeline:  frames -> 1-second windows per source MAC -> features -> RandomForest
           -> accuracy + confusion matrix -> replay with ALERTS -> (WIPS) blocklist

Data sources (pick one):
  python wids.py --synthetic                       # demo data, works instantly
  python wids.py --csv frames.csv                  # columns: time,src,dst,subtype,rssi,label
  python wids.py --pcap lab.pcap --attacker aa:bb:cc:dd:ee:ff   # your own monitor-mode capture
Add --wips to also block (log) offending MACs.

ONLY use on traffic from your own / an approved, isolated lab network.
"""
import argparse, json, random
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report, ConfusionMatrixDisplay

DEAUTH, DISASSOC = 12, 10          # 802.11 management subtypes
FEATURES = ["fps", "deauth_count", "deauth_ratio", "unique_dst", "rssi_mean", "rssi_std", "mgmt_ratio"]

# ---------- 1. Data loading ----------
def synthetic_frames(seed=42, duration=300):
    """Fake but realistic-ish frames. label 1 = attack frame."""
    rng = random.Random(seed)
    rows = []
    ap = "00:11:22:33:44:55"
    devices = [f"de:ad:be:ef:00:{i:02x}" for i in range(20)]
    rssi_base = {d: rng.randint(-80, -40) for d in devices + [ap]}
    for t in range(duration):
        for d in devices + [ap]:
            for _ in range(rng.randint(2, 40)):            # normal traffic
                st = rng.choice([0, 4, 8, 8, 8, 4])        # assoc/probe/beacon-ish; 8 beacon
                rows.append((t + rng.random(), d, rng.choice(devices + [ap]), st,
                             rssi_base[d] + rng.gauss(0, 2), 0))
            if rng.random() < 0.03:                        # benign occasional deauth (roaming)
                for _ in range(rng.randint(1, 4)):
                    rows.append((t + rng.random(), ap, rng.choice(devices), DEAUTH,
                                 rssi_base[ap] + rng.gauss(0, 2), 0))
        if 60 <= t % 100 < 75:                             # attack bursts (spoofed AP MAC)
            for _ in range(rng.randint(15, 250)):          # includes some low-rate attacks
                rows.append((t + rng.random(), ap, rng.choice(["ff:ff:ff:ff:ff:ff"] + devices),
                             DEAUTH, -35 + rng.gauss(0, 4), 1))
    return pd.DataFrame(rows, columns=["time", "src", "dst", "subtype", "rssi", "label"])

def pcap_frames(path, attacker):
    from scapy.all import rdpcap, Dot11, RadioTap
    rows = []
    for p in rdpcap(path):
        if not p.haslayer(Dot11):
            continue
        d = p[Dot11]
        rssi = getattr(p[RadioTap], "dBm_AntSignal", None) if p.haslayer(RadioTap) else None
        src = d.addr2 or "unknown"
        is_attack = int(d.subtype in (DEAUTH, DISASSOC) and src.lower() == attacker.lower()) if attacker else 0
        rows.append((float(p.time), src, d.addr1 or "unknown", d.subtype if d.type == 0 else -1,
                     rssi if rssi is not None else -90, is_attack))
    return pd.DataFrame(rows, columns=["time", "src", "dst", "subtype", "rssi", "label"])

# ---------- 2. Feature extraction ----------
def make_windows(df):
    df = df.copy()
    df["win"] = df["time"].astype(float).astype(int)
    df["is_deauth"] = df["subtype"].isin([DEAUTH, DISASSOC]).astype(int)
    df["is_mgmt"] = (df["subtype"] >= 0).astype(int)
    g = df.groupby(["win", "src"])
    out = pd.DataFrame({
        "fps": g.size(),
        "deauth_count": g["is_deauth"].sum(),
        "unique_dst": g["dst"].nunique(),
        "rssi_mean": g["rssi"].mean(),
        "rssi_std": g["rssi"].std().fillna(0),
        "mgmt_ratio": g["is_mgmt"].mean(),
        "label": g["label"].max(),          # window is malicious if it has any attack frame
    }).reset_index()
    out["deauth_ratio"] = out["deauth_count"] / out["fps"]
    return out

# ---------- 3. Train + evaluate ----------
def train(win):
    X, y = win[FEATURES], win["label"]
    Xtr, Xte, ytr, yte, _, idx_te = train_test_split(X, y, win.index, test_size=0.3,
                                                     random_state=1, stratify=y)
    clf = RandomForestClassifier(n_estimators=100, random_state=1, class_weight="balanced")
    clf.fit(Xtr, ytr)
    pred = clf.predict(Xte)
    print(f"\nAccuracy: {accuracy_score(yte, pred):.4f}")
    print(classification_report(yte, pred, target_names=["normal", "attack"], zero_division=0))
    cm = confusion_matrix(yte, pred)
    ConfusionMatrixDisplay(cm, display_labels=["normal", "attack"]).plot(cmap="Blues")
    plt.title("Deauth flood detection - confusion matrix")
    plt.savefig("confusion_matrix.png", dpi=200, bbox_inches="tight"); plt.close()
    imp = pd.Series(clf.feature_importances_, index=FEATURES).sort_values()
    imp.plot.barh(title="Feature importance"); plt.tight_layout()
    plt.savefig("feature_importance.png", dpi=200); plt.close()
    print("Saved confusion_matrix.png and feature_importance.png")
    return clf, idx_te

# ---------- 4. Detection / prevention replay ----------
def run_detector(clf, win, idx, wips):
    blocked = set()
    print("\n--- Replaying test traffic through the WIDS ---")
    for i in sorted(idx, key=lambda k: win.loc[k, "win"]):
        r = win.loc[i]
        if clf.predict(pd.DataFrame([r[FEATURES]]))[0] == 1:
            print(f"[ALERT] t={int(r.win)}s  src={r.src}  deauth_frames={int(r.deauth_count)}  fps={int(r.fps)}")
            if wips and r.src not in blocked:
                blocked.add(r.src)
                print(f"[WIPS ] blocking {r.src} (logged to blocklist.json)")
    if wips:
        json.dump(sorted(blocked), open("blocklist.json", "w"), indent=2)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--synthetic", action="store_true")
    ap.add_argument("--csv"); ap.add_argument("--pcap"); ap.add_argument("--attacker")
    ap.add_argument("--wips", action="store_true")
    a = ap.parse_args()
    if a.csv: df = pd.read_csv(a.csv)
    elif a.pcap: df = pcap_frames(a.pcap, a.attacker)
    else: df = synthetic_frames()
    win = make_windows(df)
    print(f"{len(df)} frames -> {len(win)} windows ({int(win.label.sum())} malicious)")
    clf, idx = train(win)
    run_detector(clf, win, idx, a.wips)
