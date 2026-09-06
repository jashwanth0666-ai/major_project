from pathlib import Path
import gc, json, time, warnings
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, average_precision_score, confusion_matrix, brier_score_loss
warnings.filterwarnings("ignore")

try:
    from xgboost import XGBClassifier
except ImportError:
    raise ImportError("XGBoost is required. Run: pip install xgboost")

BASE = Path(__file__).resolve().parent
SPLITS = BASE / "data" / "splits"
OUT = BASE / "data" / "phase4"
OUT.mkdir(parents=True, exist_ok=True)

FEATURES = [
"url_length","domain_length","subdomain_count","path_length","query_length",
"has_ip","has_https","has_at","has_dash","has_multiple_subdomains",
"special_char_count","digit_count","entropy","has_shortener",
"suspicious_keyword_count","dot_count","slash_count","hyphen_count",
"percent_encoded_count","query_parameter_count","uppercase_count",
"domain_digit_count","domain_entropy","path_segment_count","digit_ratio"
]

def entropy(s):
    if not s: return 0.0
    a = pd.Series(list(s)).value_counts().to_numpy(float)
    p = a/a.sum()
    return float(-(p*np.log2(p)).sum())

def engineer(df):
    df=df.copy()
    u=df.url.fillna("").astype(str)
    d=df.domain.fillna("").astype(str)
    df["dot_count"]=u.str.count(r"\.")
    df["slash_count"]=u.str.count("/")
    df["hyphen_count"]=u.str.count("-")
    df["percent_encoded_count"]=u.str.count(r"%[0-9A-Fa-f]{2}")
    df["uppercase_count"]=u.str.count(r"[A-Z]")
    q=u.str.extract(r"\?(.*)$",expand=False).fillna("")
    df["query_parameter_count"]=np.where(q.eq(""),0,q.str.count("&")+1)
    df["domain_digit_count"]=d.str.count(r"\d")
    df["domain_entropy"]=d.map(entropy).astype(np.float32)
    p=u.str.extract(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://[^/]*(/[^?#]*)?",expand=False).fillna("")
    p=p.str.strip("/")
    df["path_segment_count"]=np.where(p.eq(""),0,p.str.count("/")+1)
    df["digit_ratio"]=(df["digit_count"]/df["url_length"].replace(0,np.nan)).fillna(0).astype(np.float32)
    return df

def load(name):
    path=SPLITS/name
    print("  Loading",name)
    df=pd.read_csv(path,low_memory=False)
    need=["url","label","domain"] + [x for x in FEATURES if x in df.columns and x not in ["dot_count","slash_count","hyphen_count","percent_encoded_count","query_parameter_count","uppercase_count","domain_digit_count","domain_entropy","path_segment_count","digit_ratio"]]
    miss=[x for x in need if x not in df.columns]
    if miss: raise ValueError(f"{path} missing: {miss}")
    df=engineer(df)
    X=df[FEATURES].apply(pd.to_numeric,errors="coerce").fillna(0).astype(np.float32).to_numpy()
    y=df.label.map({"benign":0,"phishing":1})
    if y.isna().any(): raise ValueError("Unexpected labels found")
    y=y.astype(np.int8).to_numpy()
    print(f"    rows={len(y):,} phishing={y.sum():,} benign={(y==0).sum():,}")
    del df; gc.collect()
    return X,y

def metrics(y,p,t,split):
    pred=(p>=t).astype(np.int8)
    tn,fp,fn,tp=confusion_matrix(y,pred,labels=[0,1]).ravel()
    return dict(split=split,threshold=float(t),
        accuracy=accuracy_score(y,pred),precision=precision_score(y,pred,zero_division=0),
        recall=recall_score(y,pred,zero_division=0),f1=f1_score(y,pred,zero_division=0),
        roc_auc=roc_auc_score(y,p),pr_auc=average_precision_score(y,p),
        fpr=fp/(fp+tn),fnr=fn/(fn+tp),tn=int(tn),fp=int(fp),fn=int(fn),tp=int(tp),
        brier_score=brier_score_loss(y,p))

def main():
    start=time.time()
    print("="*72)
    print("AI WatchDog - PHASE 4 CALIBRATION & THRESHOLD OPTIMIZATION")
    print("="*72)

    print("\n[1/6] Loading splits...")
    Xtr,ytr=load("train.csv")
    Xv,yv=load("validation.csv")
    Xte,yte=load("test.csv")
    Xu,yu=load("unseen_domain_test.csv")

    Xcal,Xth,ycal,yth=train_test_split(Xv,yv,test_size=.5,random_state=42,stratify=yv)
    print(f"  Calibration rows: {len(ycal):,}")
    print(f"  Threshold rows:   {len(yth):,}")

    print("\n[2/6] Training XGBoost deployment candidate...")
    pos=max(int(ytr.sum()),1); neg=max(int((ytr==0).sum()),1)
    w=neg/pos
    model=XGBClassifier(
        n_estimators=350,max_depth=6,learning_rate=.08,min_child_weight=2,
        subsample=.90,colsample_bytree=.90,objective="binary:logistic",
        eval_metric="logloss",tree_method="hist",n_jobs=-1,random_state=42)
    model.fit(Xtr,ytr,sample_weight=np.where(ytr==1,w,1.0).astype(np.float32))

    print("\n[3/6] Calibrating probabilities...")
    # scikit-learn 1.6+ removed cv="prefit".
    # FrozenEstimator is the supported way to calibrate an already-trained
    # model without retraining it on the calibration set.
    try:
        from sklearn.frozen import FrozenEstimator
        cal = CalibratedClassifierCV(
            estimator=FrozenEstimator(model),
            method="isotonic",
        )
    except ImportError:
        # Compatibility with older scikit-learn versions.
        try:
            cal = CalibratedClassifierCV(
                estimator=model,
                method="isotonic",
                cv="prefit",
            )
        except TypeError:
            cal = CalibratedClassifierCV(
                base_estimator=model,
                method="isotonic",
                cv="prefit",
            )

    cal.fit(Xcal, ycal)

    print("\n[4/6] Threshold sweep...")
    pth=cal.predict_proba(Xth)[:,1]
    thresholds=np.round(np.arange(.05,.951,.01),2)
    sweep=pd.DataFrame([metrics(yth,pth,t,"threshold_selection") for t in thresholds])
    sweep.to_csv(OUT/"threshold_results.csv",index=False)

    eligible=sweep[sweep.recall>=.90]
    if len(eligible):
        best=eligible.sort_values(["f1","precision","fpr"],ascending=[False,False,True]).iloc[0]
        rule="max F1 subject to recall >= 0.90"
    else:
        best=sweep.sort_values(["f1","precision","fpr"],ascending=[False,False,True]).iloc[0]
        rule="maximum F1; no threshold reached recall >= 0.90"
    threshold=float(best.threshold)
    print(f"  Selected threshold: {threshold:.2f}")
    print(f"  Rule: {rule}")
    print(f"  F1={best.f1:.4f} Precision={best.precision:.4f} Recall={best.recall:.4f} FPR={best.fpr:.4f}")

    print("\n[5/6] Final evaluation...")
    pte=cal.predict_proba(Xte)[:,1]
    pu=cal.predict_proba(Xu)[:,1]
    test=metrics(yte,pte,threshold,"test")
    unseen=metrics(yu,pu,threshold,"unseen_domain_test")
    final=pd.DataFrame([test,unseen])
    final.to_csv(OUT/"final_threshold_results.csv",index=False)

    cal_quality=pd.DataFrame([
        dict(dataset="calibration",brier_score=brier_score_loss(ycal,cal.predict_proba(Xcal)[:,1]),roc_auc=roc_auc_score(ycal,cal.predict_proba(Xcal)[:,1]),pr_auc=average_precision_score(ycal,cal.predict_proba(Xcal)[:,1])),
        dict(dataset="threshold_selection",brier_score=brier_score_loss(yth,pth),roc_auc=roc_auc_score(yth,pth),pr_auc=average_precision_score(yth,pth)),
        dict(dataset="test",brier_score=brier_score_loss(yte,pte),roc_auc=roc_auc_score(yte,pte),pr_auc=average_precision_score(yte,pte)),
        dict(dataset="unseen_domain_test",brier_score=brier_score_loss(yu,pu),roc_auc=roc_auc_score(yu,pu),pr_auc=average_precision_score(yu,pu))
    ])
    cal_quality.to_csv(OUT/"calibration_results.csv",index=False)

    print(f"\n  TEST:   F1={test['f1']:.4f} Precision={test['precision']:.4f} Recall={test['recall']:.4f} FPR={test['fpr']:.4f} ROC-AUC={test['roc_auc']:.4f} PR-AUC={test['pr_auc']:.4f}")
    print(f"  UNSEEN: F1={unseen['f1']:.4f} Precision={unseen['precision']:.4f} Recall={unseen['recall']:.4f} FPR={unseen['fpr']:.4f} ROC-AUC={unseen['roc_auc']:.4f} PR-AUC={unseen['pr_auc']:.4f}")

    print("\n[6/6] Saving model and Risk Engine...")
    import joblib
    joblib.dump(cal,OUT/"xgboost_calibrated.joblib")
    config={
      "model":"XGBoost + isotonic calibration","selected_threshold":threshold,
      "threshold_selection_rule":rule,
      "risk_score_formula":"round(calibrated_phishing_probability * 100)",
      "risk_bands":{"0-25":"SAFE","26-50":"LOW RISK","51-75":"SUSPICIOUS","76-100":"HIGH RISK"},
      "features":FEATURES}
    (OUT/"risk_engine_config.json").write_text(json.dumps(config,indent=2),encoding="utf-8")

    report=f"""AI WatchDog - PHASE 4 REPORT
============================================================
Model: XGBoost + isotonic probability calibration
Calibration rows: {len(ycal):,}
Threshold-selection rows: {len(yth):,}
Selected threshold: {threshold:.2f}
Selection rule: {rule}

TEST
F1={test['f1']:.4f}
Precision={test['precision']:.4f}
Recall={test['recall']:.4f}
FPR={test['fpr']:.4f}
FNR={test['fnr']:.4f}
ROC-AUC={test['roc_auc']:.4f}
PR-AUC={test['pr_auc']:.4f}
Brier={test['brier_score']:.4f}

UNSEEN-DOMAIN TEST
F1={unseen['f1']:.4f}
Precision={unseen['precision']:.4f}
Recall={unseen['recall']:.4f}
FPR={unseen['fpr']:.4f}
FNR={unseen['fnr']:.4f}
ROC-AUC={unseen['roc_auc']:.4f}
PR-AUC={unseen['pr_auc']:.4f}
Brier={unseen['brier_score']:.4f}

RISK ENGINE
risk_score = round(calibrated_phishing_probability * 100)
0-25   SAFE
26-50  LOW RISK
51-75  SUSPICIOUS
76-100 HIGH RISK

The threshold was selected without using test or unseen-domain data.
Total runtime: {time.time()-start:.1f}s
"""
    (OUT/"phase4_report.txt").write_text(report,encoding="utf-8")
    print("\n"+"="*72)
    print("PHASE 4 COMPLETE")
    print("="*72)
    print(f"Outputs saved to: {OUT}")

if __name__=="__main__":
    main()
