# ML-Based Wireless Intrusion Detection / Prevention System (WIDS/WIPS)

A prototype that detects **deauthentication flood attacks** on Wi-Fi networks using a Random Forest classifier (scikit-learn). It labels traffic as normal or malicious, raises an alert on each attack, and (optionally) blocks the offending MAC address.

## How it works
1. Load 802.11 frames (time, source MAC, destination MAC, subtype, signal strength).
2. Group frames into 1-second windows per source MAC.
3. Extract 7 features: fps, deauth_count, deauth_ratio, unique_dst, rssi_mean, rssi_std, mgmt_ratio.
4. Train a Random Forest (70/30 train/test split) and report accuracy, precision/recall and a confusion matrix.
5. Replay test traffic: print an [ALERT] for each attack window. With --wips, log the attacker's MAC to blocklist.json.

## Install
    pip install scikit-learn pandas matplotlib scapy

## Run
    python wids.py --synthetic --wips

Other data sources:

    python wids.py --csv frames.csv
    python wids.py --pcap capture.pcap --attacker aa:bb:cc:dd:ee:ff

CSV columns: time, src, dst, subtype, rssi, label

## Output
- Accuracy and classification report in the terminal
- confusion_matrix.png and feature_importance.png
- blocklist.json (WIPS mode)

## Results
The included results come from synthetic data, used to validate the pipeline. Results on the AWID3 dataset will be added once access is granted.

## Limitations
- Deauth floods often spoof the real AP's MAC, so blocking by source MAC can block the legitimate AP.
- Synthetic data is easier to separate than real traffic, so 100% accuracy is not a real-world claim.

## Ethics
Capture and test attacks only on your own or an approved, isolated lab network.

## Author
Amir Fuad, Strathmore University (CNS 3204 assignment)
