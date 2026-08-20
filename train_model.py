#!/usr/bin/env python3
import os
import pickle
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from torch.utils.data import DataLoader, TensorDataset

CSV_FILE = "normal_syscall_traffic.csv"
MODEL_PATH = "hids_autoencoder.pth"
SCALER_PATH = "scaler.pkl"

# Must match the features collected in collector.py
MONITORED_SYSCALLS = [
    0, 1, 2, 3, 4, 5, 8, 9, 10, 11, 12, 13, 14, 16, 20, 21, 22, 23, 39, 41, 
    42, 43, 44, 45, 49, 50, 56, 57, 59, 60, 62, 72, 78, 87, 101, 102, 105, 257, 322, 332
]

# PyTorch Autoencoder Architecture
class SyscallAutoencoder(nn.Module):
    def __init__(self, input_dim):
        super(SyscallAutoencoder, self).__init__()
        # Encoder: 40 -> 24 -> 12 -> 8 (Latent Bottleneck)
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 24),
            nn.ReLU(),
            nn.Linear(24, 12),
            nn.ReLU(),
            nn.Linear(12, 8)
        )
        # Decoder: 8 -> 12 -> 24 -> 40
        self.decoder = nn.Sequential(
            nn.Linear(8, 12),
            nn.ReLU(),
            nn.Linear(12, 24),
            nn.ReLU(),
            nn.Linear(24, input_dim),
            nn.Sigmoid()  # Normalization maps to [0, 1]
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

    # Extract feature columns
    feature_cols = [f"sys_{s}" for s in MONITORED_SYSCALLS]
    data = df[feature_cols].values

    print(f"[+] Dataset shape: {data.shape} (Samples x Features)")

    # 1. Train / Validation Split (80% Train, 20% Val)
    train_data, val_data = train_test_split(data, test_size=0.2, random_state=42, shuffle=True)

    # 2. Fit Scaler only on Training Data
    print("[+] Normalizing feature matrix...")
    scaler = MinMaxScaler()
    train_scaled = scaler.fit_transform(train_data)
    val_scaled = scaler.transform(val_data)

    # Save fitted scaler
    with open(SCALER_PATH, "wb") as f:
        pickle.dump(scaler, f)
    print(f"[+] Scaler object saved to {SCALER_PATH}")

    # Convert to Tensors
    train_tensor = torch.tensor(train_scaled, dtype=torch.float32)
    val_tensor = torch.tensor(val_scaled, dtype=torch.float32)

    # DataLoader setup
    batch_size = 128
    train_loader = DataLoader(TensorDataset(train_tensor), batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(TensorDataset(val_tensor), batch_size=batch_size, shuffle=False)

    # Initialize Model, Loss, Optimizer
    input_dim = len(MONITORED_SYSCALLS)
    model = SyscallAutoencoder(input_dim)
    criterion = nn.MSELoss()
    optimizer = optim.Adam(model.parameters(), lr=0.001)

    epochs = 20
    print(f"[+] Training PyTorch Autoencoder for {epochs} epochs (Batch Size: {batch_size})...")

    for epoch in range(epochs):
        model.train()
        train_loss = 0.0
        for batch in train_loader:
            inputs = batch[0]
            outputs = model(inputs)
            loss = criterion(outputs, inputs)
            
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            train_loss += loss.item()

        # Validation Step
        model.eval()
        val_loss = 0.0
        with torch.no_grad():
            for batch in val_loader:
                inputs = batch[0]
                outputs = model(inputs)
                loss = criterion(outputs, inputs)
                val_loss += loss.item()

        avg_train = train_loss / len(train_loader)
        avg_val = val_loss / len(val_loader)
        print(f"Epoch [{epoch+1:02d}/{epochs:02d}] - Train Loss: {avg_train:.6f} | Val Loss: {avg_val:.6f}")

    # --- Threshold calibration on held-out benign validation data ---
    model.eval()
    with torch.no_grad():
        recon = model(val_tensor)
        errors = ((recon - val_tensor) ** 2).mean(dim=1).numpy()

    mu, sigma = float(errors.mean()), float(errors.std())
    print("\n[+] Calibration on benign validation set:")
    print(f"    Mean (mu)      : {mu:.6f}")
    print(f"    Std Dev (sigma): {sigma:.6f}")
    print(f"    tau = mu + 3s  : {mu + 3*sigma:.6f}")
    for p in (95, 99, 99.9):
        print(f"    p{p:<5}         : {np.percentile(errors, p):.6f}")

    # Save Model Weights
    torch.save(model.state_dict(), MODEL_PATH)
    print(f"[+] Training complete! Model weights saved to {MODEL_PATH}")

if __name__ == "__main__":
    main()