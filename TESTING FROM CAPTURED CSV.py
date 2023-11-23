import pandas as pd
from sklearn.preprocessing import StandardScaler
import joblib

# Load the file_to_classify
file_to_classify = pd.read_csv("C:\\Users\\alexs\\OneDrive\\Escritorio\\aalex\\Alex\\UPTP\\Cuarto Semestre\\Introduction to AI\\Assignment 1.2\\DataSampleTest2.csv", index_col=None)
file_to_classify_columns = ["Src Port", "Dst Port", "TotLen Fwd Pkts", "Fwd Pkt Len Mean", "Init Fwd Win Byts", "Fwd Seg Size Min"]
file_to_classify_dtypes = {"Src Port": int, "Dst Port": int, "TotLen Fwd Pkts": int, "Fwd Pkt Len Mean": float, "Init Fwd Win Byts": int, "Fwd Seg Size Min": int}

# Assuming you have already trained the SVM model and saved it in 'svm_model.joblib'
# Load the trained SVM model
clf = joblib.load('adaboost_model.joblib')

# Extract the features for the new data
X_file_to_classify = file_to_classify[file_to_classify_columns]

# Feature Scaling
scaler = StandardScaler()
X_file_to_classify_scaled = scaler.fit_transform(X_file_to_classify)

# Make predictions on the file_to_classify set
y_pred_file_to_classify = clf.predict(X_file_to_classify_scaled)

# Save the predicted labels to a CSV file
predictions_df = pd.DataFrame({"Predicted_Label": y_pred_file_to_classify})
predictions_df.to_csv("C:\\Users\\alexs\\OneDrive\\Escritorio\\aalex\\Alex\\UPTP\\Cuarto Semestre\\Introduction to AI\\Assignment 1.2\\DataTestSample2_results.csv", index=False)
