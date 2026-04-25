import json
import sys
from pathlib import Path

# ── Load log ──────────────────────────────────────────────────
LOG_FILE = Path("ids_log.ndjson")

if not LOG_FILE.exists():
    print("ids_log.ndjson not found. Run the IDS first.")
    sys.exit(1)

packets = []
with open(LOG_FILE) as f:
    for line in f:
        line = line.strip()
        if line:
            packets.append(json.loads(line))

print(f"Loaded {len(packets)} packets from log\n")

# ── Each anomaly type treated separately ─────────────────────
anomaly_types = ["same_ip", "oversize", "statdev",
                 "port_scan", "syn_flood", "icmp_flood"]

results = {}

for atype in anomaly_types:
    predicted = [bool(p.get(atype, False)) for p in packets]

    if atype == "same_ip":
        ground = [p["src"] == p["dst"] for p in packets]

    elif atype == "oversize":
        ground = [p["size"] > 1500 for p in packets]

    elif atype == "statdev":
        from collections import deque
        import math
        window = deque(maxlen=100)
        ground = []
        for p in packets:
            sz = p["size"]
            if len(window) >= 2:
                mean = sum(window) / len(window)
                var  = sum((x - mean)**2 for x in window) / len(window)
                sd   = math.sqrt(var)
                ground.append(sz > mean + 2*sd or sz < mean - 2*sd)
            else:
                ground.append(False)
            window.append(sz)

    elif atype == "port_scan":
        from collections import defaultdict
        tracker = defaultdict(set)
        ground  = []
        for p in packets:
            if p.get("proto") == 6 and p.get("dst_port", -1) >= 0:
                tracker[p["src"]].add(p["dst_port"])
                ground.append(len(tracker[p["src"]]) > 15)
            else:
                ground.append(False)

    elif atype == "syn_flood":
        ground.append(bool(p.get("syn_flood", False)))

    elif atype == "icmp_flood":
        from collections import defaultdict
        counter = defaultdict(int)
        ground  = []
        for p in packets:
            if p.get("proto") == 1:
                counter[p["src"]] += 1
                ground.append(counter[p["src"]] > 50)
            else:
                ground.append(False)

    TP = sum(p and g for p, g in zip(predicted, ground))
    FP = sum(p and not g for p, g in zip(predicted, ground))
    FN = sum(not p and g for p, g in zip(predicted, ground))
    TN = sum(not p and not g for p, g in zip(predicted, ground))

    precision = TP / (TP + FP) if (TP + FP) else 0
    recall    = TP / (TP + FN) if (TP + FN) else 0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) else 0)
    accuracy  = (TP + TN) / len(packets) if packets else 0

    results[atype] = dict(TP=TP, FP=FP, FN=FN, TN=TN,
                          precision=precision, recall=recall,
                          f1=f1, accuracy=accuracy)

# ── Print report ─────────────────────────────────────────────
print(f"{'Anomaly':<12} {'TP':>5} {'FP':>5} {'FN':>5} {'TN':>6} "
      f"{'Prec':>7} {'Recall':>7} {'F1':>7} {'Acc':>7}")
print("─" * 70)

for atype, r in results.items():
    print(f"{atype:<12} {r['TP']:>5} {r['FP']:>5} {r['FN']:>5} {r['TN']:>6} "
          f"{r['precision']:>7.2%} {r['recall']:>7.2%} "
          f"{r['f1']:>7.2%} {r['accuracy']:>7.2%}")

# ── Overall ───────────────────────────────────────────────────
all_g = []
all_pred = []

for pkt in packets:
    g = any(pkt.get(a, False) for a in anomaly_types)
    p = any(pkt.get(a, False) for a in anomaly_types)
    all_g.append(g)
    all_pred.append(p)

TP = sum(p and g for p, g in zip(all_pred, all_g))
FP = sum(p and not g for p, g in zip(all_pred, all_g))
FN = sum(not p and g for p, g in zip(all_pred, all_g))
TN = sum(not p and not g for p, g in zip(all_pred, all_g))

prec = TP/(TP+FP) if (TP+FP) else 0
rec  = TP/(TP+FN) if (TP+FN) else 0
f1   = 2*prec*rec/(prec+rec) if (prec+rec) else 0
acc  = (TP+TN)/len(packets) if packets else 0

print("─" * 70)
print(f"{'OVERALL':<12} {TP:>5} {FP:>5} {FN:>5} {TN:>6} "
      f"{prec:>7.2%} {rec:>7.2%} {f1:>7.2%} {acc:>7.2%}")
