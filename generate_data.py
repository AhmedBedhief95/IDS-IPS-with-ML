import json
import os
import random

def generate_mock_data():
    if not os.path.exists('datasets'):
        os.makedirs('datasets')
    
    data = []
    for _ in range(500):
        # Info: Small packets, standard protocols
        data.append({"proto": random.choice([6, 17]), "size": random.randint(40, 500), "label": 0})
        # Medium: Odd sizes or ICMP
        data.append({"proto": 1, "size": random.randint(500, 1500), "label": 1})
        # High: Massive packets (potential DDoS/Exfiltration)
        data.append({"proto": random.choice([6, 17]), "size": random.randint(2000, 5000), "label": 2})

    with open('datasets/training_data.json', 'w') as f:
        json.dump(data, f)
    print("Synthetic dataset created in /datasets/training_data.json")

if __name__ == "__main__":
    generate_mock_data()
