
import warnings
import pandas as pd
from pandas import DataFrame
import joblib
import numpy as np
from numpy import ndarray
import ipaddress
from tqdm import tqdm
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

from pandas.errors import SettingWithCopyWarning
warnings.simplefilter(action="ignore", category=SettingWithCopyWarning)


def load_data(path: str, Numpy: bool=True):
    if Numpy==True:
        return np.genfromtxt(path, delimiter=',')
    else:
        return pd.read_csv(path)


def get_features(data: DataFrame, optimal_features: list, train: bool=True) -> DataFrame:

    if train==True:
        # Add 'label' to columns to be used
        train_features = optimal_features.copy()
        train_features.append('label')
        # Extract columns to be sued from full dataset
        data_optimal_features = data[train_features]

        return data_optimal_features
    else:
        # Extract columns to be sued from full dataset   
        data_optimal_features = data[optimal_features]

        return data_optimal_features


def label_data(data: DataFrame, column: str, label_mapping: dict) -> DataFrame:


    progress_bar = tqdm(total=len(data), desc='Label Encoding', unit=" rows")

    for i, value in enumerate(data[column]):
        data.at[i, column] = label_mapping[value]
        progress_bar.update(1)

    progress_bar.close()

    data[column] = data[column].astype('int64')

    return data


def undersample_data(data: DataFrame, label_column: str) -> DataFrame:

    value_counts = data[label_column].value_counts()
    mean_count = value_counts.mean()

    undersampled_data = pd.DataFrame(columns=data.columns)

    for value, count in value_counts.items():
        if count > mean_count:
            undersampled_count = int((count / value_counts.sum()) * mean_count)
            subset = data[data[label_column] == value].sample(n=undersampled_count, random_state=42)
            undersampled_data = pd.concat([undersampled_data, subset], ignore_index=True)
        else:
            subset = data[data[label_column] == value]
            undersampled_data = pd.concat([undersampled_data, subset], ignore_index=True)

    # Randomize the undersampled data
    randomized_data = undersampled_data.sample(frac=1, random_state=42)

    return randomized_data


def convert_to_float(data: DataFrame) -> DataFrame:
    if 'tcp_flags_str' in data.columns or 'tcp_flags_fin' in data.columns:
        # Drop the 'tcp_flags_str' and 'tcp_flags_fin' column
        data = data.drop(['tcp_flags_str', 'tcp_flags_fin'], axis=1)
    for col in data.columns:
        converted_values = []
        for value in data[col]:
            if pd.isna(value):
                converted_values.append(-3)
            elif isinstance(value, (int, float)):
                converted_values.append(float(value))
            elif isinstance(value, str):
                try:
                    if value.startswith('0x'):
                        converted_values.append(int(value, 16))
                    elif '.' in value:
                        parts = value.split('.')
                        if len(parts) == 4:
                            ip = ipaddress.ip_address(value)
                            converted_values.append(int(ip))
                        else:
                            converted_values.append(float(value))
                    else:
                        converted_values.append(-4)
                except ValueError:
                    converted_values.append(-4)
                except ipaddress.AddressValueError:
                    converted_values.append(-4)
            else:
                converted_values.append(-4)
            

        data[col] = converted_values
        data[col] = data[col].astype('float64')


    return data


def split(data: DataFrame, target_col: str):
    X = data.drop(target_col, axis=1) # Inputs
    y = data[target_col] # Target

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, 
                                                        random_state=42, 
                                                        stratify=y,
                                                        shuffle=True)
    
    return X_train, X_test, y_train, y_test


def scale_data(data: DataFrame=None, 
               X_train: DataFrame=None, 
               X_test: DataFrame=None, 
               train: bool=True):

    if train ==True:
        scaler = StandardScaler().fit(X_train)
        joblib.dump(scaler, '/Users/rohan/Desktop/ScienceFair/src/features/scaler.pkl')
        scaler = joblib.load('/Users/rohan/Desktop/ScienceFair/src/features/scaler.pkl')

        X_train_scaled = scaler.transform(X_train)
        X_test_scaled = scaler.transform(X_test)

        return X_train_scaled, X_test_scaled
    
    else:
        scaler = joblib.load('/Users/rohan/Desktop/ScienceFair/src/features/scaler.pkl')
        data_scaled = scaler.transform(data)

        return data_scaled

label_mapping: dict={
                    'normal':0, 'dos_synflooding':1, 'mirai_ackflooding':2, 'host_discovery':3,
                    'telnet_bruteforce':4, 'mirai_httpflooding':5, 'mirai_udpflooding':6,
                    'mitm_arpspoofing':7, 'scanning_host':8, 'scanning_port':9, 'scanning_os':10
                    }

def preprocess(data: DataFrame,
               train: bool=True,
               save: bool=True,
               path: str = './data/processed/',
               label_col: str = 'label',
               optimal_features: list=[
                'timestamp', 'ip_len', 'ip_id', 'ip_flags', 'ip_ttl', 'ip_proto',
                'ip_checksum', 'ip_dst', 'ip_dst_host','tcp_srcport', 'tcp_dstport',
                'tcp_port', 'tcp_stream', 'tcp_completeness', 'tcp_seq_raw', 'tcp_ack',
                'tcp_ack_raw', 'tcp_flags_reset', 'tcp_flags_syn', 'tcp_window_size_value',
                'tcp_window_size', 'tcp_window_size_scalefactor', 'tcp_', 'udp_srcport',
                'udp_dstport', 'udp_port', 'udp_length', 'udp_time_delta', 'eth_dst_oui',
                'eth_addr_oui', 'eth_dst_lg', 'eth_lg', 'eth_ig', 'eth_src_oui', 'eth_type',
                'icmp_type', 'icmp_code', 'icmp_checksum', 'icmp_checksum_status', 'arp_opcode'
                ],
                label_mapping: dict={
                    'normal':0, 'dos_synflooding':1, 'mirai_ackflooding':2, 'host_discovery':3,
                    'telnet_bruteforce':4, 'mirai_httpflooding':5, 'mirai_udpflooding':6,
                    'mitm_arpspoofing':7, 'scanning_host':8, 'scanning_port':9, 'scanning_os':10
                    }):

    if train==True:
        data = get_features(data, optimal_features, train=True)
        data = label_data(data, label_col, label_mapping)
        data = undersample_data(data, label_col)
        data = convert_to_float(data)
        X_train, X_test, y_train, y_test = split(data, label_col)
        X_train_scaled, X_test_scaled = scale_data(X_train=X_train,
                                                   X_test=X_test,
                                                   train=True)

        y_train = y_train.astype(int)
        y_test = y_test.astype(int)
        if save==True:
            np.savetxt(str(path+'X_train_scaled.csv'), X_train_scaled, delimiter=',')
            np.savetxt(str(path+'X_test_scaled.csv'), X_test_scaled, delimiter=',')
            y_train.to_csv(str(path+'y_train.csv'), index=False, header=True, mode='w')
            y_test.to_csv(str(path+'y_test.csv'), index=False, header=True, mode='w')


        return X_train_scaled, X_test_scaled, y_train, y_test
    
    else:
        data = get_features(data, optimal_features, train=False)
        data = convert_to_float(data)
        data = scale_data(data=data, train=False)

        return data
    
def inference_preprocess(data: DataFrame) -> ndarray:
    optimal_features=[
        'timestamp', 'ip_len', 'ip_id', 'ip_flags', 'ip_ttl', 'ip_proto',
        'ip_checksum', 'ip_dst', 'ip_dst_host','tcp_srcport', 'tcp_dstport',
        'tcp_port', 'tcp_stream', 'tcp_completeness', 'tcp_seq_raw', 'tcp_ack',
        'tcp_ack_raw', 'tcp_flags_reset', 'tcp_flags_syn', 'tcp_window_size_value',
        'tcp_window_size', 'tcp_window_size_scalefactor', 'tcp_', 'udp_srcport',
        'udp_dstport', 'udp_port', 'udp_length', 'udp_time_delta', 'eth_dst_oui',
        'eth_addr_oui', 'eth_dst_lg', 'eth_lg', 'eth_ig', 'eth_src_oui', 'eth_type',
        'icmp_type', 'icmp_code', 'icmp_checksum', 'icmp_checksum_status', 'arp_opcode'
        ]
    scaler = joblib.load('/Users/rohan/Desktop/ScienceFair/src/features/scaler.pkl')

    data_optimal_features = data[optimal_features]
    data_floats = convert_to_float(data_optimal_features)
    data_scaled = scaler.transform(data_floats)

    return data_scaled


