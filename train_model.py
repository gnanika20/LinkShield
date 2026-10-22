import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)


# ==========================================
# 1. Load dataset
# ==========================================

df = pd.read_csv("phishing_features_new.csv")

print("Dataset shape:", df.shape)


# ==========================================
# 2. Separate features and label
# ==========================================

X = df.drop("label", axis=1)
y = df["label"]


# ==========================================
# 3. Train-test split
# ==========================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))


# ==========================================
# 4. Define models
# ==========================================

models = {

    "Logistic Regression": Pipeline([
        ("scaler", StandardScaler()),
        ("model", LogisticRegression(
            max_iter=1000,
            random_state=42
        ))
    ]),

    "Decision Tree": DecisionTreeClassifier(
        random_state=42,
        max_depth=10
    ),

    "Random Forest": RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        n_jobs=-1,
        max_depth=15
    )
}


# ==========================================
# 5. Train and evaluate
# ==========================================

results = {}

best_model = None
best_f1 = 0
best_model_name = ""


for name, model in models.items():

    print("\n" + "=" * 50)
    print(name)
    print("=" * 50)

    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    cm = confusion_matrix(y_test, y_pred)

    print(f"Accuracy : {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall   : {recall:.4f}")
    print(f"F1 Score : {f1:.4f}")

    print("\nConfusion Matrix:")
    print(cm)

    print("\nClassification Report:")
    print(classification_report(
        y_test,
        y_pred,
        target_names=["Legitimate", "Phishing"]
    ))

    results[name] = {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1
    }

    # Select best model using F1 score
    if f1 > best_f1:
        best_f1 = f1
        best_model = model
        best_model_name = name


# ==========================================
# 6. Display comparison
# ==========================================

print("\n\n" + "=" * 60)
print("MODEL COMPARISON")
print("=" * 60)

for name, metrics in results.items():

    print(
        f"{name:20s} "
        f"Accuracy={metrics['accuracy']:.4f}  "
        f"Precision={metrics['precision']:.4f}  "
        f"Recall={metrics['recall']:.4f}  "
        f"F1={metrics['f1']:.4f}"
    )


# ==========================================
# 7. Save best model
# ==========================================

print("\nBest model:", best_model_name)
print("Best F1 Score:", round(best_f1, 4))

joblib.dump(
    best_model,
    "phishing_model_new.pkl"
)

print("\nModel saved as:")
print("phishing_model_new.pkl")