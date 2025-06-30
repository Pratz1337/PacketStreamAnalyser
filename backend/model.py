import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import confusion_matrix, classification_report
from scipy import stats
import joblib # Import joblib

# Adding TensorFlow and Keras imports for deep learning
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Conv1D, MaxPooling1D, Flatten, Dropout, BatchNormalization
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
from tensorflow.keras.utils import to_categorical

# Configure GPU usage - only use GPU for model training
gpus = tf.config.experimental.list_physical_devices('GPU')
if gpus:
    try:
        # Allow memory growth to avoid allocating all GPU memory at once
        for gpu in gpus:
            tf.config.experimental.set_memory_growth(gpu, True)
        print(f"Found {len(gpus)} GPU(s), configured for memory growth")
    except RuntimeError as e:
        print(f"GPU configuration error: {e}")
else:
    print("No GPU found, using CPU")

# Utility functions for feature analysis
def get_feature_types(df):
    numeric = df.select_dtypes(include=[np.number]).columns.tolist()
    categorical = df.select_dtypes(exclude=[np.number]).columns.tolist()
    return numeric, categorical

def correlation_analysis(df, features):
    corr = df[features].corr().abs()
    high = []
    for i in range(len(corr.columns)):
        for j in range(i+1, len(corr.columns)):
            f1, f2 = corr.columns[i], corr.columns[j]
            val = corr.iat[i, j]
            if val > 0.8:
                high.append((f1, f2, val))
    return high

def calculate_outliers_percentage(df):
    Q1, Q3 = df.quantile(0.25), df.quantile(0.75)
    IQR = Q3 - Q1
    out = ((df < (Q1 - 1.5 * IQR)) | (df > (Q3 + 1.5 * IQR))).sum()
    return (out / len(df)) * 100

def analyze_variance_homogeneity(df, features):
    res = {}
    for feat in features:
        groups = [grp[feat].values for _, grp in df.groupby('Attack Type')]
        stat, p = stats.levene(*groups)
        res[feat] = {'Statistic': stat, 'p-value': p}
    return res


# New function to prepare data for CNN
def prepare_data_for_cnn(data, target_col='Attack Type', test_size=0.2):
    """
    Prepares the dataset for CNN training by scaling features and encoding labels.
    
    Parameters:
    data (DataFrame): The input dataframe
    target_col (str): The column containing target labels
    test_size (float): Proportion of data to use for testing
    
    Returns:
    X_train, X_test, y_train, y_test, encoder, feature_names, scaler: Prepared data, label encoder, feature names, and the fitted scaler
    """
    # Separate features and target
    X = data.drop(columns=[target_col])
    y = data[target_col]
    
    feature_names = list(X.columns) # Get feature names
    
    # Encode the target variable
    encoder = LabelEncoder()
    y_encoded = encoder.fit_transform(y)
    
    # Split data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=test_size, random_state=42, stratify=y_encoded
    )
    
    # Scale the features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train) # Fit and transform training data
    X_test_scaled = scaler.transform(X_test)       # Only transform test data
    
    # Reshape input data for CNN: (samples, timesteps, features)
    # For CNN, we treat each feature as a "timestep"
    X_train_cnn = X_train_scaled.reshape(X_train_scaled.shape[0], X_train_scaled.shape[1], 1)
    X_test_cnn = X_test_scaled.reshape(X_test_scaled.shape[0], X_test_scaled.shape[1], 1)
    
    # Convert to categorical for multi-class classification
    y_train_cat = to_categorical(y_train)
    y_test_cat = to_categorical(y_test)
    
    return X_train_cnn, X_test_cnn, y_train_cat, y_test_cat, encoder, feature_names, scaler # Return scaler

# Function to build a complex CNN model
def build_cnn_model(input_shape, num_classes):
    """
    Builds a complex CNN model with multiple layers
    
    Parameters:
    input_shape (tuple): Shape of input data (timesteps, features)
    num_classes (int): Number of output classes
    
    Returns:
    model: Compiled Keras model
    """
    model = Sequential()
    
    # First convolutional block
    model.add(Conv1D(filters=64, kernel_size=3, activation='relu', input_shape=input_shape))
    model.add(BatchNormalization())
    model.add(MaxPooling1D(pool_size=2))
    model.add(Dropout(0.2))
    
    # Second convolutional block
    model.add(Conv1D(filters=128, kernel_size=3, activation='relu'))
    model.add(BatchNormalization())
    model.add(MaxPooling1D(pool_size=2))
    model.add(Dropout(0.3))
    
    # Third convolutional block
    model.add(Conv1D(filters=256, kernel_size=3, activation='relu'))
    model.add(BatchNormalization())
    model.add(MaxPooling1D(pool_size=2))
    model.add(Dropout(0.4))
    
    # Flatten layer
    model.add(Flatten())
    
    # Dense layers
    model.add(Dense(512, activation='relu'))
    model.add(BatchNormalization())
    model.add(Dropout(0.5))
    
    model.add(Dense(256, activation='relu'))
    model.add(BatchNormalization())
    model.add(Dropout(0.5))
    
    # Output layer
    model.add(Dense(num_classes, activation='softmax'))
    
    # Compile model
    model.compile(
        optimizer='adam',
        loss='categorical_crossentropy',
        metrics=['accuracy']
    )
    
    return model

# Function to train and evaluate the CNN model
def train_and_evaluate_cnn(X_train, X_test, y_train, y_test, encoder, epochs=20, batch_size=64):
    """
    Trains and evaluates the CNN model
    
    Parameters:
    X_train, X_test, y_train, y_test: Training and testing data
    encoder: Label encoder used to transform class labels
    epochs: Number of training epochs
    batch_size: Batch size for training
    
    Returns:
    model: Trained model
    history: Training history
    """
    # Define input shape and number of classes
    input_shape = (X_train.shape[1], 1)
    num_classes = len(encoder.classes_)
    
    try:
        # Check if GPU is available and functional
        if len(tf.config.list_physical_devices('GPU')) > 0:
            print("GPU is available. Attempting to use GPU for both model creation and training...")
            
            # Create and train model on GPU
            strategy = tf.distribute.OneDeviceStrategy(device="/GPU:0")
            with strategy.scope():
                model = build_cnn_model(input_shape, num_classes)
                model.summary()
                
                # Define callbacks
                callbacks = [
                    EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True),
                    ModelCheckpoint('best_cnn_model.keras', save_best_only=True, monitor='val_accuracy')
                ]
                
                # Train on GPU
                print("Starting model training on GPU...")
                history = model.fit(
                    X_train, y_train,
                    epochs=epochs,
                    batch_size=batch_size,
                    validation_split=0.2,
                    callbacks=callbacks,
                    verbose=1
                )
        else:
            raise ValueError("No GPU available")
            
    except (ValueError, RuntimeError, tf.errors.InvalidArgumentError) as e:
        print(f"Error using GPU: {e}")
        print("Falling back to CPU for both model creation and training...")
        
        # Create and train model on CPU
        with tf.device('/CPU:0'):
            model = build_cnn_model(input_shape, num_classes)
            model.summary()
            
            # Define callbacks
            callbacks = [
                EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True),
                ModelCheckpoint('best_cnn_model.keras', save_best_only=True, monitor='val_accuracy')
            ]
            
            # Train on CPU
            print("Starting model training on CPU...")
            history = model.fit(
                X_train, y_train,
                epochs=epochs,
                batch_size=batch_size,
                validation_split=0.2,
                callbacks=callbacks,
                verbose=1
            )
    
    # Evaluate the model on CPU to be safe
    with tf.device('/CPU:0'):
        print("Evaluating model...")
        loss, accuracy = model.evaluate(X_test, y_test, verbose=0)
        print(f'Test Accuracy: {accuracy:.4f}')
        
        # Make predictions
        y_pred_prob = model.predict(X_test)
        y_pred = np.argmax(y_pred_prob, axis=1)
        y_test_classes = np.argmax(y_test, axis=1)
        
        # Calculate confusion matrix and classification report
        print("\nConfusion Matrix:")
        cm = confusion_matrix(y_test_classes, y_pred)
        class_labels = encoder.classes_
        plt.figure(figsize=(12, 10))
        sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=class_labels, yticklabels=class_labels)
        plt.xlabel("Predicted Label")
        plt.ylabel("True Label")
        plt.title("Confusion Matrix")
        plt.show()
        
        print("\nClassification Report:")
        print(classification_report(y_test_classes, y_pred, target_names=class_labels))
        
        # Plot training history
        plt.figure(figsize=(12, 5))
        plt.subplot(1, 2, 1)
        plt.plot(history.history['accuracy'], label='Training Accuracy')
        plt.plot(history.history['val_accuracy'], label='Validation Accuracy')
        plt.title('Model Accuracy')
        plt.xlabel('Epoch')
        plt.ylabel('Accuracy')
        plt.legend()
        
        plt.subplot(1, 2, 2)
        plt.plot(history.history['loss'], label='Training Loss')
        plt.plot(history.history['val_loss'], label='Validation Loss')
        plt.title('Model Loss')
        plt.xlabel('Epoch')
        plt.ylabel('Loss')
        plt.legend()
        plt.tight_layout()
        plt.show()
    
    return model, history

dfs = []

# Load the datasets
for dirname, _, filenames in os.walk('/kaggle/input/'):
    for filename in filenames:
        dfs.append(pd.read_csv(os.path.join(dirname, filename)))


for i, data in enumerate(dfs, start=1):
    rows, cols = data.shape
    print(f'df{i} -> {rows} rows, {cols} columns')

data = pd.concat(dfs, axis=0, ignore_index=True)


for df in dfs: del df


data.head()


data.sample(n=10, random_state=42)


print(f"Dataset Dimensions: {data.shape}")

# Display data types
data.info()

# Checking for missing values
missing_values = data.isna().sum()
missing_percentage = (missing_values / len(data)) * 100

# Printing columns with missing values
for column, count in missing_values.items():
    if count != 0:
        print(f"Column '{column}' has {count} missing values, which is {missing_percentage[column]:.2f}% of the total")

# Removal of leading/trailing whitespace
col_names = {col: col.strip() for col in data.columns}
data.rename(columns = col_names, inplace = True)

# Checking and counting duplicates
duplicates = data.duplicated()
duplicate_count = duplicates.sum()

# Output results
print(f"Number of duplicate rows: {duplicate_count}")

data = data.drop_duplicates(keep='first')
del duplicates
data.shape

# %% [markdown]
# The same can be done for columns

# Identify columns with identical data
identical_columns = {}
columns = data.columns
list_control = columns.copy().tolist()

# Compare each pair of columns
for col1 in columns:
    for col2 in columns:
        if col1 != col2:
            if data[col1].equals(data[col2]):
                if (col1 not in identical_columns) and (col1 in list_control):
                    identical_columns[col1] = [col2]
                    list_control.remove(col2)
                elif (col1 in identical_columns) and (col1 in list_control):
                    identical_columns[col1].append(col2)
                    list_control.remove(col2)

# Print the result
if identical_columns:
    print("Identical columns found:")
    for key, value in identical_columns.items():
        print(f"'{key}' is identical to {value}")
else: print("No identical columns found.")

# Removing the columns with duplicated values
for key, value in identical_columns.items():
    data.drop(columns=value, inplace=True)

print(data.columns)
data.shape

# Checking for infinite values
num_columns = data.select_dtypes(include = np.number).columns
has_infinite = np.isinf(data[num_columns]).sum()
print(has_infinite[has_infinite > 0])

# Removing infinite values is typically safe and beneficial, as it enhances data integrity, ensures statistical accuracy, aids in proper model training, and clarifies insights.

# Treating infinite values
data.replace([np.inf, -np.inf], np.nan, inplace=True)

# ## 2.1. Missing Values
# 
# There are different approaches to dealing with missing values. The first step in identifying how to proceed is to understand their impact on the dataset. Here, we will do that by analyzing the y column (Label).

# Attack counts
attack_counts = data['Label'].value_counts().reset_index()
attack_counts.columns = ['Attack Type', 'Number of Occurrences']

# Duplicating the df and dropping rows with missing values
data_no_na = data.dropna()

# Counting the total number of occurrences of each attack after dropping
occurrences_nonull = data_no_na['Label'].value_counts().reset_index()
occurrences_nonull.columns = ['Attack Type', 'Occurrences w/o Null Rows']

# Merging the DataFrames
attack_counts = attack_counts.merge(occurrences_nonull, on='Attack Type', how='left')

# Calculating the difference
attack_counts['Abs Difference'] = attack_counts['Number of Occurrences'] - attack_counts['Occurrences w/o Null Rows']
attack_counts['Difference %'] = ((attack_counts['Abs Difference'] * 100) / attack_counts['Number of Occurrences']).round(2)

# Visualization
attack_counts

# Cleaning up
del data_no_na

# Evaluating percentage of missing values per column
threshold = 10
missing_percentage = (data.isnull().sum() / len(data)) * 100

# Filter columns with missing values over the threshold
high_missing_cols = missing_percentage[missing_percentage > threshold]

# Print columns with high missing percentages
if len(high_missing_cols) > 0:
    print(f'The following columns have over {threshold}% of missing values:')
    print(high_missing_cols)
else:
    print('There are no columns with missing values greater than the threshold')

# The analysis of missing values across the dataset suggests that missing values are not heavily concentrated in any single column and that the dataset can tolerate row-wise removal without significant impact.

row_missing_percentage = (data.isna().sum(axis=1) / data.shape[1]) * 100
print(row_missing_percentage.describe())

missing_rows = data.isna().any(axis=1).sum()
print(f'\nTotal rows with missing values: {missing_rows}')


data = data.dropna()
print(f'Dataset shape after row-wise removal: {data.shape}')


only_unique_cols = []
for col in data.columns:
    if len(data[col].unique()) == 1:
        only_unique_cols.append(col)
        print(col)

print(f'\nThe number of columns with only one unique values is: {len(only_unique_cols)}')

data.drop(only_unique_cols, axis=1, inplace=True)
del only_unique_cols


data.shape

group_mapping = {
    'BENIGN': 'Normal Traffic',
    'DoS Hulk': 'DoS',
    'DDoS': 'DDoS',
    'PortScan': 'Port Scanning',
    'DoS GoldenEye': 'DoS',
    'FTP-Patator': 'Brute Force',
    'DoS slowloris': 'DoS',
    'DoS Slowhttptest': 'DoS',
    'SSH-Patator': 'Brute Force',
    'Bot': 'Bots',
    'Web Attack � Brute Force': 'Web Attacks',
    'Web Attack � XSS': 'Web Attacks',
    'Infiltration': 'Infiltration',
    'Web Attack � Sql Injection': 'Web Attacks',
    'Heartbleed': 'Miscellaneous'
}

# Map to new group column
data['Attack Type'] = data['Label'].map(group_mapping)

# Checking the new values
data['Attack Type'].value_counts()


data.drop(columns='Label', inplace=True)

# Removing rows with statistically irrelevant attack types
data.drop(data[(data['Attack Type'] == 'Infiltration') | (data['Attack Type'] == 'Miscellaneous')].index, inplace=True)

# Data shape and attack counts after removal
print(data.shape)
data['Attack Type'].value_counts()

data.sample(10)

data.describe()

# Correlation Analysis:
numeric_features, categorical_features = get_feature_types(data)
high_corr = correlation_analysis(data, numeric_features)

# Printing the pairs with high correlation and isolating the near/perfect multicollinearity
high_multicollinearity = []
for item in high_corr:
    print(f'{item[0]} has a high correlation with {item[1]}: {item[2].round(4)}')
    if item[2] >= 0.95:
        high_multicollinearity.append(item)

# Plotting the pairs with very high correlation for better visualization

n_plots = len(high_multicollinearity)
n_cols = 4
n_rows = (n_plots + n_cols - 1) // n_cols

fig, axes = plt.subplots(n_rows, n_cols, figsize=(18, n_rows * 4))
axes = axes.flatten()

for i, item in enumerate(high_multicollinearity):
    feature_x = item[0]
    feature_y = item[1]
    corr_value = item[2]

    # Scatter plot
    sns.scatterplot(x=data[feature_x], y=data[feature_y], ax=axes[i])
    axes[i].set_title(f'{feature_x} vs {feature_y} (Corr={corr_value:.2f})', fontsize=8)
    axes[i].set_xlabel(feature_x, fontsize=8)
    axes[i].set_ylabel(feature_y, fontsize=8)

# Hide any unused subplots
for j in range(len(high_multicollinearity), len(axes)):
    fig.delaxes(axes[j])

plt.tight_layout()
plt.show()

# Removal of columns based on correlation analysis
selected_columns = ['Total Backward Packets', 'Total Length of Bwd Packets', 'Subflow Bwd Bytes', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size']

# dropping columns with perfect/near perfect multicollinearity
data.drop(columns=selected_columns, inplace=True)

# Updating the variables and checking dataset shape
numeric_features, categorical_features = get_feature_types(data)
data.shape

# Calculate outliers percentage
outlier_percentages = calculate_outliers_percentage(data[numeric_features])

# Convert to DataFrame for easier manipulation
outliers_df = pd.DataFrame({'Outlier_Percentage': outlier_percentages})

# Define the threshold for concern
threshold = 10

# Identify features with high percentage of outliers
high_outlier_features = outliers_df[outliers_df['Outlier_Percentage'] > threshold]

# Plot the outlier percentages and highlight features above the threshold
plt.figure(figsize=(15, 10))
outliers_df.sort_values(by='Outlier_Percentage', ascending=False).plot(kind='bar', legend=False, figsize=(20, 5))
plt.axhline(y=threshold, color='r', linestyle='--', label=f'{threshold}% Threshold')
plt.xlabel('Features')
plt.ylabel('Percentage of Outliers')
plt.title('Percentage of Outliers for Each Feature with Threshold')
plt.legend()
plt.show()

# Print the features with high outlier percentages
print(f"Features with outlier percentage above {threshold}%:\n")
print(high_outlier_features.sort_values('Outlier_Percentage', ascending=False))

# Cleaning up
del outliers_df

# ## 3.4. Data Distribution
# 
# Understanding the distribution of the data is fundamental for selecting the right preprocessing and modeling techniques. Data distribution also gives insights towards the best statistic tests to perform.

norm_dist = 0
not_norm_dist = 0

for col in numeric_features:

    # Perform Anderson-Darling test for normality
    result = stats.anderson(data[col], dist='norm')

    # Compare the statistic with the critical value at 5% significance level
    if result.statistic < result.critical_values[2]:  # 5% significance level
        norm_dist += 1
    else:
        not_norm_dist += 1

print(f'{norm_dist} features are normally distributed')
print(f'{not_norm_dist} features are not normally distributed - Reject null hypothesis')

# Count occurrences of each attack type and convert to a DataFrame
attack_counts_df = data['Attack Type'].value_counts().reset_index()
attack_counts_df.columns = ['Attack Type', 'Number of Occurrences']

# Counting the total for each attack on both cases
total_occurrences = attack_counts_df['Number of Occurrences'].sum()

# Calculating the respective percentages
attack_counts_df['% of Total'] = ((attack_counts_df['Number of Occurrences'] / total_occurrences) * 100).round(2)

print(attack_counts_df)

# Cleaning up
del attack_counts_df

# Applying the Levene's Test
# p-value < 0.05 suggests unequal variances among groups (rejecting the null hypothesis of equal variances)

# Removing statiscally irrelavant features from the dataset
cols_to_remove = ['ECE Flag Count', 'RST Flag Count', 'Fwd URG Flags', 'Idle Std', 'Fwd PSH Flags', 'Active Std', 'Down/Up Ratio', 'URG Flag Count']
data.drop(columns=cols_to_remove, errors='ignore', inplace=True)

# Update numeric_features after removing columns
numeric_features, categorical_features = get_feature_types(data)

# Now perform variance homogeneity test with updated feature list
variance_result = analyze_variance_homogeneity(data, numeric_features)

# Analysing the results
no_significant_results = True

for feature, result in variance_result.items():   
    if result['p-value'] > 0.05:  
        print(f"\nFeature: {feature}")  
        print(f"  - Test Statistic: {result['Statistic']:.4f}")  
        print(f"  - p-value: {result['p-value']:.4f}")  
        print("  - Interpretation: The variances are not significantly different (fail to reject null hypothesis).")  
        no_significant_results = False

# If no features had p-values > 0.05  
if no_significant_results:  
    print("\nNo features have p-values greater than 0.05. All features have significant differences in variance.")



# Remove these Random Forest related visualizations and variables
# Removing statiscally irrelavant features from the dataset
cols_to_remove = ['ECE Flag Count', 'RST Flag Count', 'Fwd URG Flags', 'Idle Std', 'Fwd PSH Flags', 'Active Std', 'Down/Up Ratio', 'URG Flag Count']
data.drop(columns=cols_to_remove, errors='ignore', inplace=True)

# Prepare data for CNN model
print("Preparing data for CNN model...")
X_train, X_test, y_train, y_test, label_encoder, feature_names, scaler = prepare_data_for_cnn(data) # Capture feature_names and scaler
print(f"X_train shape: {X_train.shape}")
print(f"X_test shape: {X_test.shape}")
print(f"y_train shape: {y_train.shape}")
print(f"y_test shape: {y_test.shape}")
print(f"Classes: {label_encoder.classes_}")

# Train and evaluate CNN model
print("\nTraining CNN model...")
cnn_model, history = train_and_evaluate_cnn(
    X_train, X_test, y_train, y_test, label_encoder, epochs=30, batch_size=128
)

# Save the trained model
cnn_model.save('malicious_traffic_cnn_model.keras')
print("Model saved as 'malicious_traffic_cnn_model.keras'")

# Save the preprocessed data, feature names, and scaler for future use
np.save('X_test.npy', X_test)
np.save('y_test.npy', y_test)
np.save('label_encoder_classes.npy', label_encoder.classes_)
np.save('feature_columns.npy', np.array(feature_names)) 
joblib.dump(scaler, 'scaler.joblib') # Save the scaler
print("Test data, label encoder, feature columns, and scaler saved for future inference")

# Clean dataset to a CSV file
data.to_csv('cicids2017_cleaned.csv', index=False)