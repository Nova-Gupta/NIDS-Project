import streamlit as st
import numpy as np
import pandas as pd
import pickle

# Page config MUST be first
st.set_page_config(page_title="NIDS App", layout="centered", page_icon="🛡️")

# Load model and all metadata
@st.cache_resource
def load_model_and_metadata():
    try:
        model = pickle.load(open('./models/nids_model.pkl', 'rb'))
        scaler = pickle.load(open('./models/scaler.pkl', 'rb'))
        label_encoders = pickle.load(open('./models/label_encoders.pkl', 'rb'))
        selected_features = pickle.load(open('./models/selected_features.pkl', 'rb'))
        categorical_values = pickle.load(open('./models/categorical_values.pkl', 'rb'))
        metadata = pickle.load(open('./models/model_metadata.pkl', 'rb'))
        
        return model, scaler, label_encoders, selected_features, categorical_values, metadata
    except FileNotFoundError as e:
        st.error(f"Model files not found: {e}")
        st.error("Please run the training script first to generate the model files.")
        return None, None, None, None, None, None

# Load everything
model, scaler, label_encoders, selected_features, categorical_values, metadata = load_model_and_metadata()

if model is None:
    st.stop()

# Main title
st.title("🛡️ Network Intrusion Detection System")
st.markdown("Enter network traffic details below to check if it's **Normal** or an **Attack**.")

# Display model info
with st.expander("📊 Model Information"):
    st.write(f"**Model Type:** {metadata['model_type']}")
    st.write(f"**Features Used:** {metadata['n_features']} out of 41 total features")
    st.write(f"**Selected Features:** {', '.join(selected_features)}")

# Function to create input fields based on selected features
def create_input_fields():
    inputs = {}
    
    # Organize features by category for better UX
    connection_features = ['duration', 'src_bytes', 'dst_bytes', 'hot', 'logged_in']
    traffic_features = ['count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'same_srv_rate', 'diff_srv_rate']
    host_features = [f for f in selected_features if 'dst_host' in f]
    categorical_features = ['protocol_type', 'service', 'flag']
    other_features = [f for f in selected_features if f not in connection_features + traffic_features + host_features + categorical_features]
    
    # Create columns for better layout
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🔗 Connection Features")
        for feature in connection_features:
            if feature in selected_features:
                if feature == 'logged_in':
                    inputs[feature] = st.checkbox("Logged In", value=False)
                else:
                    inputs[feature] = st.number_input(
                        f"{feature.replace('_', ' ').title()}", 
                        min_value=0.0, 
                        step=1.0 if feature in ['duration', 'src_bytes', 'dst_bytes', 'hot'] else 0.01
                    )
    
    with col2:
        st.subheader("📊 Traffic Features")
        for feature in traffic_features:
            if feature in selected_features:
                if 'rate' in feature:
                    inputs[feature] = st.slider(
                        f"{feature.replace('_', ' ').title()}", 
                        0.0, 1.0, 0.0, 0.01
                    )
                else:
                    inputs[feature] = st.number_input(
                        f"{feature.replace('_', ' ').title()}", 
                        min_value=0, 
                        step=1
                    )
    
    # Categorical features
    st.subheader("📋 Network Protocol Details")
    col3, col4, col5 = st.columns(3)
    
    with col3:
        if 'protocol_type' in selected_features:
            protocol_options = categorical_values['protocol_type'].tolist()
            inputs['protocol_type'] = st.selectbox("Protocol Type", protocol_options)
    
    with col4:
        if 'service' in selected_features:
            service_options = categorical_values['service'].tolist()
            inputs['service'] = st.selectbox("Service", service_options[:20])  # Show first 20 services
    
    with col5:
        if 'flag' in selected_features:
            flag_options = categorical_values['flag'].tolist()
            inputs['flag'] = st.selectbox("Flag", flag_options)
    
    # Host features
    if host_features:
        st.subheader("🖥️ Host Features")
        host_col1, host_col2 = st.columns(2)
        
        with host_col1:
            for i, feature in enumerate(host_features):
                if i % 2 == 0:
                    if 'rate' in feature:
                        inputs[feature] = st.slider(
                            f"{feature.replace('_', ' ').title()}", 
                            0.0, 1.0, 0.0, 0.01
                        )
                    else:
                        inputs[feature] = st.number_input(
                            f"{feature.replace('_', ' ').title()}", 
                            min_value=0, 
                            step=1
                        )
        
        with host_col2:
            for i, feature in enumerate(host_features):
                if i % 2 == 1:
                    if 'rate' in feature:
                        inputs[feature] = st.slider(
                            f"{feature.replace('_', ' ').title()}", 
                            0.0, 1.0, 0.0, 0.01
                        )
                    else:
                        inputs[feature] = st.number_input(
                            f"{feature.replace('_', ' ').title()}", 
                            min_value=0, 
                            step=1
                        )
    
    # Other features
    if other_features:
        st.subheader("🔧 Other Features")
        for feature in other_features:
            if 'rate' in feature:
                inputs[feature] = st.slider(
                    f"{feature.replace('_', ' ').title()}", 
                    0.0, 1.0, 0.0, 0.01
                )
            else:
                inputs[feature] = st.number_input(
                    f"{feature.replace('_', ' ').title()}", 
                    min_value=0, 
                    step=1
                )
    
    return inputs

# Create input fields
inputs = create_input_fields()

# Prediction button
if st.button("🔍 Analyze Traffic", type="primary"):
    try:
        # Prepare input array
        input_array = []
        
        for feature in selected_features:
            if feature in ['protocol_type', 'service', 'flag']:
                # Encode categorical features
                encoded_value = label_encoders[feature].transform([inputs[feature]])[0]
                input_array.append(encoded_value)
            elif feature == 'logged_in':
                input_array.append(int(inputs[feature]))
            else:
                input_array.append(float(inputs[feature]))
        
        # Convert to numpy array and reshape
        input_array = np.array(input_array).reshape(1, -1)
        
        # Scale the input
        input_scaled = scaler.transform(input_array)
        
        # Make prediction
        prediction = model.predict(input_scaled)[0]
        prediction_proba = model.predict_proba(input_scaled)[0]
        
        # Display results
        st.markdown("---")
        st.markdown("## 🔍 Analysis Result:")
        
        if prediction == 0:
            st.success("✅ **Normal Traffic Detected**")
            confidence = prediction_proba[0]
            st.info(f"Confidence: {confidence:.1%}")
        else:
            st.error("🚨 **Intrusion Detected!**")
            confidence = prediction_proba[1]
            st.warning(f"Threat Level: {confidence:.1%}")
        
        # Show detailed confidence scores
        st.markdown("### 📊 Confidence Scores:")
        col_normal, col_attack = st.columns(2)
        
        with col_normal:
            st.metric("Normal Traffic", f"{prediction_proba[0]:.1%}")
        
        with col_attack:
            st.metric("Attack Traffic", f"{prediction_proba[1]:.1%}")
        
        # Show input summary
        with st.expander("📋 Input Summary"):
            st.write("**Provided Input Values:**")
            for feature, value in inputs.items():
                st.write(f"- **{feature.replace('_', ' ').title()}:** {value}")
                
    except Exception as e:
        st.error(f"Error during prediction: {str(e)}")
        st.info("Please check your input values and try again.")

# Example data section
st.markdown("---")
with st.expander("📋 Sample Data"):
    st.markdown("""
    **Example Normal Traffic:**
    - Duration: 0, Protocol: tcp, Service: http, Flag: SF
    - Source Bytes: 239, Destination Bytes: 486
    - Count: 8, Service Count: 8, Error Rates: 0.0
    
    **Example Attack Traffic:**
    - Duration: 0, Protocol: tcp, Service: http, Flag: REJ
    - Source Bytes: 0, Destination Bytes: 0
    - Count: 1, Service Count: 2, Error Rates: 1.0
    """)

# Footer
st.markdown("---")
st.caption("Made by Nova | NSL-KDD Dataset | Machine Learning Project")
st.caption(f"Model: {metadata['model_type']} | Features: {metadata['n_features']}")