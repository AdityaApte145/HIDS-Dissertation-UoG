#!/usr/bin/env python3
import torch
import torch.nn as nn
import torch.optim as optim
import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler
import os
import pickle

CSV_FILE = "normal_syscall_traffic.csv"
MODEL_PATH = "hids_autoencoder.pth"
SCALER_PATH = "scaler_min_max.npy"

# Must match the features collected in collector.py
MONITORED_SYSCALLS = [
    0, 1, 2, 3, 4, 5, 8, 9, 10, 11, 12, 13, 14, 16, 20, 21, 22, 23, 39, 41, 
    42, 43, 44, 45, 49, 50, 56, 57, 59, 60, 62, 72, 78, 87, 101, 102, 105, 257, 322, 332
]

# PyTorch Autoencoder Architecture
class SyscallAutoencoder(nn.Module):
    def __init__(self, input_dim):
        super(SyscallAutoencoder, self).__init__()
        # Encoder: Compresses 40 syscall features down to a latent bottleneck of 8 dimensions
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 24),
            nn.ReLU(),
            nn.Linear(24, 12),
            nn.ReLU(),
            nn.Linear(12, 8)
        )
        # Decoder: Reconstructs the 8 dimensions back up to 40 features
        self.decoder = nn.Sequential(
            nn.Linear(8, 12),
            nn.ReLU(),
            nn.Linear(12, 24),
            nn.ReLU(),
            nn.Linear(24, input_dim),
            nn.Sigmoid() # Keeps outputs scaled between 0 and 1
        )

    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

def main():
    if not os.path.exists(CSV_FILE):
        print(f"[!] Error: {CSV_FILE} not found. Run collector.py first!")
        return

    print(f"[+] Loading baseline dataset from {CSV_FILE}...")
    df = pd.read_csv(CSV_FILE)

    # Extract only the feature columns (sys_0, sys_1, etc.)
    feature_cols = [f"sys_{s}" for s in MONITORED_SYSCALLS]
    data = df[feature_cols].values

    print(f"[+] Dataset shape: {data.shape} (Samples x Features)")

    # Normalize data between 0.0 and 1.0 using MinMaxScaler
    print("[+] Normalizing feature matrix...")
    scaler = MinMaxScaler()
    data_scaled = scaler.fit_transform(data)

    # Save the fitted scaler object using pickle
    with open("scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)
    print("[+] Scaler object saved to scaler.pkl")
    # Convert to PyTorch Tensors
    tensor_data = torch.tensor(data_scaled, dtype=torch.float32)

    # Initialize Model, Loss Function, and Optimizer
    input_dim = len(MONITORED_SYSCALLS)
    model = SyscallAutoencoder(input_dim)
    criterion = nn.MSELoss() # Mean Squared Error reconstruction loss
    optimizer = optim.Adam(model.parameters(), lr=0.001)

    epochs = 50
    batch_size = 64
    dataset = torch.utils.data.TensorDataset(tensor_data)
    dataloader = torch.utils.data.DataLoader(dataset, batch_size=batch_size, shuffle=True)

    print(f"[+] Training PyTorch Autoencoder for {epochs} epochs...")
    model.train()
    for epoch in range(epochs):
        epoch_loss = 0
        for batch in dataloader:
            inputs = batch[0]
            
            # Forward pass
            outputs = model(inputs)
            loss = criterion(outputs, inputs)
            
            # Backward pass & optimize
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            
            epoch_loss += loss.item()

        if (epoch + 1) % 10 == 0 or epoch == 0:
            print(f"Epoch [{epoch+1}/{epochs}], Loss: {epoch_loss/len(dataloader):.6f}")

    # Save the trained model weights
    torch.save(model.state_dict(), MODEL_PATH)
    print(f"[+] Training complete! Model weights saved to {MODEL_PATH}")

if __name__ == "__main__":
    main()
