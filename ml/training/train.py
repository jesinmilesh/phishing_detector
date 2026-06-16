import os
import sys
import random
import pandas as pd
import numpy as np
import joblib
from datetime import datetime

# Add project root to path to resolve imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score
from joblib import Parallel, delayed

from ml.feature_extraction.feature_extractor import extract_features, get_feature_names
from app.config import Config

# Mirror print statements to training log file
import builtins
_print = builtins.print
def print(*args, **kwargs):
    import logging
    msg = " ".join(str(arg) for arg in args)
    _print(msg, **kwargs)
    try:
        logging.getLogger('training_logger').info(msg)
    except Exception:
        pass

# Try to import xgboost
try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

# Try to import lightgbm
try:
    import lightgbm as lgb
    LIGHTGBM_AVAILABLE = True
except ImportError:
    LIGHTGBM_AVAILABLE = False

# Set random seed for reproducibility
random.seed(42)
np.random.seed(42)

def clean_label(val):
    if pd.isna(val):
        return None
    val_str = str(val).strip().lower()
    if val_str in ['1', '1.0', 'phishing', 'phish', 'suspicious', '1']:
        return 1
    if val_str in ['0', '0.0', 'legitimate', 'legit', 'safe', '0']:
        return 0
    return None

def load_unified_dataset():
    """Loads and merges all datasets from the datasets directory dynamically."""
    print("[*] Loading datasets dynamically...")
    datasets_dir = "datasets"
    
    dfs = []
    if os.path.exists(datasets_dir):
        for f in os.listdir(datasets_dir):
            if f.endswith('.csv') or f.endswith('.xlsx') or f.endswith('.xls'):
                path = os.path.join(datasets_dir, f)
                try:
                    if f.endswith('.csv'):
                        df = pd.read_csv(path)
                    else:
                        df = pd.read_excel(path)
                    print(f"    Loaded {f} dataset ({len(df)} rows)")
                    df.columns = [col.lower().strip() for col in df.columns]
                    
                    if 'url' not in df.columns or 'label' not in df.columns:
                        col_map = {}
                        for col in df.columns:
                            if col in ['url_string', 'link', 'address']:
                                col_map[col] = 'url'
                            elif col in ['class', 'target', 'phish', 'phishing', 'is_phishing']:
                                col_map[col] = 'label'
                        df = df.rename(columns=col_map)
                    
                    if 'url' in df.columns and 'label' in df.columns:
                        dfs.append(df[['url', 'label']])
                    else:
                        print(f"    [!] Skipping {f}: Missing 'url' or 'label' column. Columns: {list(df.columns)}")
                except Exception as e:
                    print(f"    [!] Error loading {f}: {e}")
            
    if not dfs:
        raise FileNotFoundError("No valid datasets loaded. Make sure CSV/Excel files are present in the 'datasets/' folder.")
        
    unified_df = pd.concat(dfs, ignore_index=True)
    initial_len = len(unified_df)
    
    unified_df['label'] = unified_df['label'].apply(clean_label)
    unified_df = unified_df.dropna(subset=['url', 'label'])
    unified_df['label'] = unified_df['label'].astype(int)
    
    unified_df = unified_df.drop_duplicates(subset=['url'])
    final_len = len(unified_df)
    print(f"[+] Unified dataset statistics:")
    print(f"    - Initial rows: {initial_len}")
    print(f"    - Final rows after clean & deduplication: {final_len} (Removed {initial_len - final_len} records)")
    
    class_counts = unified_df['label'].value_counts()
    print(f"    - Legitimate: {class_counts.get(0, 0)} ({class_counts.get(0, 0)/final_len*100:.2f}%)")
    print(f"    - Phishing: {class_counts.get(1, 0)} ({class_counts.get(1, 0)/final_len*100:.2f}%)")
    
    return unified_df

def train_and_evaluate_models():
    os.makedirs(os.path.dirname(Config.MODEL_PATH), exist_ok=True)
    
    df = load_unified_dataset()
    
    print("[*] Extracting features from URLs in parallel...")
    # Extract features in parallel using joblib
    features_list = Parallel(n_jobs=-1)(
        delayed(extract_features)(url, False) for url in df['url']
    )
        
    X = pd.DataFrame(features_list)[get_feature_names()]
    y = df['label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    print(f"\n[*] Training dataset size: {X_train.shape[0]} samples")
    print(f"[*] Testing dataset size: {X_test.shape[0]} samples")
    
    models = {
        "Random Forest": RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, class_weight='balanced'),
        "Decision Tree": DecisionTreeClassifier(max_depth=10, random_state=42, class_weight='balanced'),
        "Gradient Boosting": GradientBoostingClassifier(n_estimators=100, learning_rate=0.1, max_depth=5, random_state=42),
        "Logistic Regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000, random_state=42, class_weight='balanced'))
    }
    
    if XGBOOST_AVAILABLE:
        neg_count = sum(y_train == 0)
        pos_count = sum(y_train == 1)
        scale_pos_weight = neg_count / pos_count if pos_count > 0 else 1.0
        models["XGBoost"] = xgb.XGBClassifier(n_estimators=100, max_depth=6, scale_pos_weight=scale_pos_weight, random_state=42, eval_metric='logloss')
    else:
        print("[!] XGBoost not available. Skipping XGBoost model training.")
        
    if LIGHTGBM_AVAILABLE:
        models["LightGBM"] = lgb.LGBMClassifier(n_estimators=100, random_state=42, verbosity=-1)
    else:
        print("[!] LightGBM not available. Skipping LightGBM model training.")
        
    best_model_name = None
    best_model_obj = None
    best_f1 = -1.0
    best_metrics = {}
    
    comparison_results = []
    
    for name, clf in models.items():
        print(f"\n[*] Training {name} Classifier...")
        try:
            # Measure time and memory roughly
            import time
            t0 = time.time()
            clf.fit(X_train, y_train)
            train_time = time.time() - t0
            
            # Predict
            t_inf = time.time()
            y_pred = clf.predict(X_test)
            inf_time = (time.time() - t_inf) / len(X_test) * 1000  # Latency per sample in ms
            
            if hasattr(clf, "predict_proba"):
                y_prob = clf.predict_proba(X_test)[:, 1]
            elif hasattr(clf, "decision_function"):
                y_prob = clf.decision_function(X_test)
            else:
                y_prob = y_pred
                
            acc = accuracy_score(y_test, y_pred)
            prec = precision_score(y_test, y_pred, zero_division=0)
            rec = recall_score(y_test, y_pred, zero_division=0)
            f1 = f1_score(y_test, y_pred, zero_division=0)
            roc = roc_auc_score(y_test, y_prob)
            cm = confusion_matrix(y_test, y_pred)
            
            print(f"    - Train Time:  {train_time:.2f}s")
            print(f"    - Latency:     {inf_time:.4f}ms/sample")
            print(f"    - Accuracy:    {acc:.4f}")
            print(f"    - Precision:   {prec:.4f}")
            print(f"    - Recall:      {rec:.4f}")
            print(f"    - F1 Score:    {f1:.4f}")
            print(f"    - ROC-AUC:     {roc:.4f}")
            
            comparison_results.append({
                "Model": name,
                "Accuracy": acc,
                "Precision": prec,
                "Recall": rec,
                "F1 Score": f1,
                "ROC-AUC": roc,
                "Latency_ms": inf_time,
                "Train_Time_s": train_time
            })
            
            if f1 > best_f1:
                best_f1 = f1
                best_model_name = name
                best_model_obj = clf
                best_metrics = {
                    "accuracy": acc,
                    "precision": prec,
                    "recall": rec,
                    "f1_score": f1,
                    "roc_auc": roc,
                    "confusion_matrix": cm.tolist(),
                    "latency_ms": inf_time
                }
        except Exception as e:
            print(f"    [!] Error training {name}: {e}")
            
    print("\n" + "="*95)
    print(f"{'MODEL COMPARISON REPORT':^95}")
    print("="*95)
    print(f"{'Classifier Name':<22} | {'Accuracy':<8} | {'Precision':<9} | {'Recall':<8} | {'F1 Score':<8} | {'ROC-AUC':<8} | {'Latency (ms)':<12}")
    print("-"*95)
    for res in comparison_results:
        print(f"{res['Model']:<22} | {res['Accuracy']:<8.4f} | {res['Precision']:<9.4f} | {res['Recall']:<8.4f} | {res['F1 Score']:<8.4f} | {res['ROC-AUC']:<8.4f} | {res['Latency_ms']:<12.4f}")
    print("="*95)
    
    print(f"\n[+] Automatically selected best model: {best_model_name} (F1 Score: {best_f1:.4f})")
    
    # Generate timestamped filename for versioning
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    versioned_filename = f"phishing_model_{timestamp}.pkl"
    model_dir = os.path.dirname(Config.MODEL_PATH)
    versioned_path = os.path.join(model_dir, versioned_filename)
    
    print(f"[*] Saving model version data to {versioned_path}...")
    model_payload = {
        'model': best_model_obj,
        'model_name': best_model_name,
        'feature_names': get_feature_names(),
        'metrics': best_metrics,
        'all_comparison_results': comparison_results
    }
    
    # Save versioned copy
    joblib.dump(model_payload, versioned_path)
    
    # Save standard/fallback active model path copy
    joblib.dump(model_payload, Config.MODEL_PATH)
    print("[+] Models saved successfully!")
    
    # Register in DB Registry and set as active
    try:
        from database.db_manager import DatabaseManager
        db = DatabaseManager()
        version_id = db.register_model(
            model_path=versioned_path,
            accuracy=best_metrics['accuracy'],
            precision=best_metrics['precision'],
            recall=best_metrics['recall'],
            f1_score=best_metrics['f1_score'],
            roc_auc=best_metrics['roc_auc'],
            dataset_version=timestamp,
            is_active=1,
            metrics_dict={
                "best_model_name": best_model_name,
                "best_metrics": best_metrics,
                "comparison": comparison_results
            }
        )
        print(f"[+] Model registered in DB as version {version_id}")
    except Exception as e:
        print(f"[-] Failed to register model in database registry: {e}")

    with open(os.path.join(model_dir, 'model_report.json'), 'w') as f:
        import json
        json.dump({
            "best_model_name": best_model_name,
            "best_metrics": best_metrics,
            "comparison": comparison_results
        }, f, indent=4)
        
    return best_model_name, best_metrics

if __name__ == "__main__":
    train_and_evaluate_models()
