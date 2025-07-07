import streamlit as st
import pickle
import numpy as np

model = pickle.load(open("models/nids_model.pkl", "rb"))

st.title("Network Intrusion Detection")

# Accept user input
duration = st.number_input("Duration")
# ... other features

features = np.array([[duration, ...]])
if st.button("Predict"):
    result = model.predict(features)
    st.write("Prediction:", "Attack" if result[0]==1 else "Normal")
