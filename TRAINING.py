import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import AdaBoostClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import joblib  # Import joblib for model serialization
import matplotlib.pyplot as plt
import numpy as np
from sklearn.feature_selection import SelectFromModel


# Load the dataset
data_columns = ["Src Port", "Dst Port", "TotLen Fwd Pkts", "Fwd Pkt Len Mean", "Init Fwd Win Byts", "Fwd Seg Size Min", "Label"]
data_dtypes = {"Src Port": int, "Dst Port": int, "TotLen Fwd Pkts": int, "Fwd Pkt Len Mean": float, "Init Fwd Win Byts": int, "Fwd Seg Size Min": int, "Label": str}

raw_data = pd.read_csv("C:\\Users\\alexs\\Downloads\\datasets\\primeras_50000_combinado.csv", usecols=data_columns, dtype=data_dtypes, index_col=None)

# Split the data into training and testing sets
X = raw_data.drop(columns=["Label"])
y = raw_data["Label"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42) 

# Feature Scaling
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Instantiate and train the AdaBoost classifier with a Decision Tree as the base estimator
base_estimator = DecisionTreeClassifier(max_depth=1)  # You can adjust the hyperparameters of the base estimator
n_estimators = 50  # You can adjust the number of weak learners (trees)

clf = AdaBoostClassifier(base_estimator=base_estimator, n_estimators=n_estimators, random_state=42)
clf.fit(X_train_scaled, y_train)



# Save the trained model using joblib
joblib.dump(clf, 'adaboost_model.joblib')

# Make predictions on the test set
y_pred = clf.predict(X_test_scaled)

# Evaluate the model
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, average='weighted')
recall = recall_score(y_test, y_pred, average='weighted')
f1 = f1_score(y_test, y_pred, average='weighted')
confusion = confusion_matrix(y_test, y_pred)

# Print the evaluation metrics
print("Accuracy:", accuracy)
print("Precision:", precision)
print("Recall:", recall)
print("F1 Score:", f1)
print("Confusion Matrix:")
print(confusion)


# features = X_train.columns.values
# importances = clf.feature_importances_
# indices = np.argsort(importances)[:-30:-1]
# plt.figure(figsize=(10,10))
# plt.title('Feature Importances')
# plt.barh(range(len(indices)), importances[indices], color='b', align='center')
# plt.yticks(range(len(indices)), [features[i] for i in indices])
# plt.xlabel('Relative Importance')
# plt.show()