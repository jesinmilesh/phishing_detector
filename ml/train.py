import os
import sys
import random
import pandas as pd
import numpy as np
import joblib

# Add project root to path to resolve imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score

from config import Config
from ml.feature_extractor import extract_features, get_feature_names

# Try to import xgboost
try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

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
    """Loads and merges all datasets from the datasets directory."""
    print("[*] Loading datasets...")
    dataset_files = {
        "phishing1": "datasets/phishing1.csv",
        "phishing2": "datasets/phishing2.csv",
        "phishing3": "datasets/phishing3.csv",
        "legitimate": "datasets/legitimate.csv"
    }
    
    dfs = []
    for name, path in dataset_files.items():
        if os.path.exists(path):
            try:
                df = pd.read_csv(path)
                print(f"    Loaded {name} dataset ({len(df)} rows)")
                # Standardize column names
                df.columns = [col.lower().strip() for col in df.columns]
                
                # Check for required columns
                if 'url' not in df.columns or 'label' not in df.columns:
                    # Try to map columns if they have different names
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
                    print(f"    [!] Skipping {name}: Missing 'url' or 'label' column. Columns found: {list(df.columns)}")
            except Exception as e:
                print(f"    [!] Error loading {name}: {e}")
        else:
            print(f"    [!] Dataset file not found: {path}")
            
    if not dfs:
        raise FileNotFoundError("No valid datasets loaded. Make sure CSV files are present in the 'datasets/' folder.")
        
    unified_df = pd.concat(dfs, ignore_index=True)
    initial_len = len(unified_df)
    
    # Preprocessing
    # 1. Clean labels
    unified_df['label'] = unified_df['label'].apply(clean_label)
    unified_df = unified_df.dropna(subset=['url', 'label'])
    unified_df['label'] = unified_df['label'].astype(int)
    
    # 2. Remove duplicates
    unified_df = unified_df.drop_duplicates(subset=['url'])
    final_len = len(unified_df)
    print(f"[+] Unified dataset statistics:")
    print(f"    - Initial rows: {initial_len}")
    print(f"    - Final rows after clean & deduplication: {final_len} (Removed {initial_len - final_len} records)")
    
    # 3. Class balance check
    class_counts = unified_df['label'].value_counts()
    print(f"    - Legitimate: {class_counts.get(0, 0)} ({class_counts.get(0, 0)/final_len*100:.2f}%)")
    print(f"    - Phishing: {class_counts.get(1, 0)} ({class_counts.get(1, 0)/final_len*100:.2f}%)")
    
    return unified_df

def train_and_evaluate_models():
    # Make sure output directory exists
    os.makedirs(os.path.dirname(Config.MODEL_PATH), exist_ok=True)
    
    df = load_unified_dataset()
    
    print("[*] Extracting features from URLs...")
    features_list = []
    for idx, row in df.iterrows():
        if idx > 0 and idx % 400 == 0:
            print(f"    Processed {idx}/{len(df)} URLs...")
        features_list.append(extract_features(row['url'], online=False))
        
    X = pd.DataFrame(features_list)[get_feature_names()]
    y = df['label']
    
    # Train/test split with stratify to maintain class ratios
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    print(f"\n[*] Training dataset size: {X_train.shape[0]} samples")
    print(f"[*] Testing dataset size: {X_test.shape[0]} samples")
    
    # Define models dictionary
    models = {
        "Random Forest": RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, class_weight='balanced'),
        "Decision Tree": DecisionTreeClassifier(max_depth=10, random_state=42, class_weight='balanced'),
        "Gradient Boosting": GradientBoostingClassifier(n_estimators=100, learning_rate=0.1, max_depth=5, random_state=42),
        "Logistic Regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000, random_state=42, class_weight='balanced'))
    }
    
    if XGBOOST_AVAILABLE:
        # Calculate scale_pos_weight for class imbalance
        neg_count = sum(y_train == 0)
        pos_count = sum(y_train == 1)
        scale_pos_weight = neg_count / pos_count if pos_count > 0 else 1.0
        models["XGBoost"] = xgb.XGBClassifier(n_estimators=100, max_depth=6, scale_pos_weight=scale_pos_weight, random_state=42, eval_metric='logloss')
    else:
        print("[!] XGBoost not available. Skipping XGBoost model training.")
        
    best_model_name = None
    best_model_obj = None
    best_f1 = -1.0
    best_metrics = {}
    
    comparison_results = []
    
    for name, clf in models.items():
        print(f"\n[*] Training {name} Classifier...")
        try:
            clf.fit(X_train, y_train)
            
            # Predict
            y_pred = clf.predict(X_test)
            
            # Predict probabilities for ROC-AUC
            if hasattr(clf, "predict_proba"):
                y_prob = clf.predict_proba(X_test)[:, 1]
            elif hasattr(clf, "decision_function"):
                y_prob = clf.decision_function(X_test)
            else:
                y_prob = y_pred
                
            # Compute metrics
            acc = accuracy_score(y_test, y_pred)
            prec = precision_score(y_test, y_pred, zero_division=0)
            rec = recall_score(y_test, y_pred, zero_division=0)
            f1 = f1_score(y_test, y_pred, zero_division=0)
            roc = roc_auc_score(y_test, y_prob)
            cm = confusion_matrix(y_test, y_pred)
            
            print(f"    - Accuracy:  {acc:.4f}")
            print(f"    - Precision: {prec:.4f}")
            print(f"    - Recall:    {rec:.4f}")
            print(f"    - F1 Score:  {f1:.4f}")
            print(f"    - ROC-AUC:   {roc:.4f}")
            
            comparison_results.append({
                "Model": name,
                "Accuracy": acc,
                "Precision": prec,
                "Recall": rec,
                "F1 Score": f1,
                "ROC-AUC": roc
            })
            
            # Update best model based on F1-Score
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
                    "confusion_matrix": cm.tolist()
                }
        except Exception as e:
            print(f"    [!] Error training {name}: {e}")
            
    # Print comparison table
    print("\n" + "="*80)
    print(f"{'MODEL COMPARISON REPORT':^80}")
    print("="*80)
    print(f"{'Classifier Name':<25} | {'Accuracy':<10} | {'Precision':<10} | {'Recall':<10} | {'F1 Score':<10} | {'ROC-AUC':<10}")
    print("-"*80)
    for res in comparison_results:
        print(f"{res['Model']:<25} | {res['Accuracy']:<10.4f} | {res['Precision']:<10.4f} | {res['Recall']:<10.4f} | {res['F1 Score']:<10.4f} | {res['ROC-AUC']:<10.4f}")
    print("="*80)
    
    print(f"\n[+] Automatically selected best model: {best_model_name} (F1 Score: {best_f1:.4f})")
    
    # Save Model data
    print(f"[*] Saving best model data to {Config.MODEL_PATH}...")
    joblib.dump({
        'model': best_model_obj,
        'model_name': best_model_name,
        'feature_names': get_feature_names(),
        'metrics': best_metrics,
        'all_comparison_results': comparison_results
    }, Config.MODEL_PATH)
    print("[+] Model saved successfully!")
    
    # Generate static report file for the frontend dashboard
    model_report_dir = os.path.dirname(Config.MODEL_PATH)
    with open(os.path.join(model_report_dir, 'model_report.json'), 'w') as f:
        import json
        json.dump({
            "best_model_name": best_model_name,
            "best_metrics": best_metrics,
            "comparison": comparison_results
        }, f, indent=4)
        
    return best_model_name, best_metrics

if __name__ == "__main__":
    train_and_evaluate_models()
