import pandas as pd
import json
import os
import joblib
from sklearn.ensemble import RandomForestClassifier

def train_ips():
    data_list = []
    for filename in os.listdir('datasets'):
        if filename.endswith('.json'):
            with open(f'datasets/{filename}') as f:
                d = json.load(f)
                data_list.extend(d) if isinstance(d, list) else data_list.append(d)

    df = pd.DataFrame(data_list)
    X = df[['proto', 'size']] 
    y = df['label']

    model = RandomForestClassifier(n_estimators=100)
    model.fit(X, y)
    joblib.dump(model, 'ips_model.pkl')
    print("Machine Learning Model Trained Successfully!")

if __name__ == "__main__":
    train_ips()
