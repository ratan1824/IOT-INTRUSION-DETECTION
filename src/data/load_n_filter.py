import os
import pandas as pd
from tqdm import tqdm
from src.data.pcap_to_csv import pcapng_to_csv
import src.data.data_filters as data_filters
from src.utils.pipeline_log_config import pipeline as logger


def scan_directory(directory: str, extension: str) -> list:
    files = []
    for filename in os.listdir(directory):
        if filename.endswith(extension):
            files.append(filename)
    return files


def load_and_filter_file(pcap_filepath: str, destination_path: str, pick_up: bool = False):
    filename = os.path.basename(pcap_filepath)
    dest_csv = os.path.join(destination_path, filename[:-5] + ".csv")

    # Skip conversion if file already exists and pick_up flag is set.
    if pick_up and os.path.exists(dest_csv):
        logger.info(f"{filename} already converted. Skipping due to pick_up flag.")
        return pd.read_csv(dest_csv)

    try:
        logger.info(f"Converting {filename} to CSV...")
        # Convert pcap to CSV and save to an interim folder.
        interim_folder = './data/interim'
        if not os.path.exists(interim_folder):
            os.makedirs(interim_folder)
        pcapng_to_csv(PCAPNG_FILE=pcap_filepath, CSV_FOLDER_PATH=interim_folder)

        # Read the interim CSV file.
        interim_csv = os.path.join(interim_folder, filename[:-5] + ".csv")
        data_df = pd.read_csv(interim_csv)

        logger.info(f"Adding labels to {filename[:-5]}.csv...")

        # Apply appropriate filter based on the filename.
        if "benign-dec.pcap" in filename:
            data_labelled = data_filters.benign_dec(data_df)
        elif "mitm-arpspoofing-1-dec.pcap" in filename or "mitm-arpspoofing-2-dec.pcap" in filename or "mitm-arpspoofing-3-dec.pcap" in filename:
            data_labelled = data_filters.mitm_arpspoofing_1_3_dec_filter(data_df)
        elif "mitm-arpspoofing-4-dec.pcap" in filename or "mitm-arpspoofing-5-dec.pcap" in filename or "mitm-arpspoofing-6-dec.pcap" in filename:
            data_labelled = data_filters.mitm_arpspoofing_4_6_dec_filter(data_df)
        elif "dos-synflooding-1-dec.pcap" in filename or "dos-synflooding-2-dec.pcap" in filename:
            data_labelled = data_filters.dos_synflooding_1_2_dec_filter(data_df)
        elif "dos-synflooding-3-dec.pcap" in filename:
            data_labelled = data_filters.dos_synflooding_3_dec_filter(data_df)
        elif "dos-synflooding-4-dec.pcap" in filename or "dos-synflooding-5-dec.pcap" in filename or "dos-synflooding-6-dec.pcap" in filename:
            data_labelled = data_filters.dos_synflooding_4_6_dec_filter(data_df)
        elif "scan-hostport-1-dec.pcap" in filename:
            data_labelled = data_filters.scan_hostport_1_dec_filter(data_df)
        elif "scan-hostport-2-dec.pcap" in filename:
            data_labelled = data_filters.scan_hostport_2_dec_filter(data_df)
        elif "scan-hostport-3-dec.pcap" in filename:
            data_labelled = data_filters.scan_hostport_3_dec_filter(data_df)
        elif "scan-hostport-4-dec.pcap" in filename:
            data_labelled = data_filters.scan_hostport_4_dec_filter(data_df)
        elif "scan-hostport-5-dec.pcap" in filename:
            data_labelled = data_filters.scan_hostport_5_dec_filter(data_df)
        elif "scan-hostport-6-dec.pcap" in filename:
            data_labelled = data_filters.scan_hostport_6_dec_filter(data_df)
        elif "scan-portos-1-dec.pcap" in filename or "scan-portos-2-dec.pcap" in filename or "scan-portos-3-dec.pcap" in filename:
            data_labelled = data_filters.scan_portos_1_3_dec_filter(data_df)
        elif "scan-portos-4-dec.pcap" in filename or "scan-portos-5-dec.pcap" in filename or "scan-portos-6-dec.pcap" in filename:
            data_labelled = data_filters.scan_portos_4_6_dec_filter(data_df)
        elif "mirai-udpflooding-1-dec.pcap" in filename or "mirai-udpflooding-2-dec.pcap" in filename or "mirai-udpflooding-3-dec.pcap" in filename or "mirai-udpflooding-4-dec.pcap" in filename:
            data_labelled = data_filters.mirai_udpflooding_1_4_dec_filter(data_df)
        elif "mirai-ackflooding-1-dec.pcap" in filename or "mirai-ackflooding-2-dec.pcap" in filename or "mirai-ackflooding-3-dec.pcap" in filename or "mirai-ackflooding-4-dec.pcap" in filename:
            data_labelled = data_filters.mirai_ackflooding_1_4_dec_filter(data_df)
        elif "mirai-httpflooding-1-dec.pcap" in filename or "mirai-httpflooding-2-dec.pcap" in filename or "mirai-httpflooding-3-dec.pcap" in filename or "mirai-httpflooding-4-dec.pcap" in filename:
            data_labelled = data_filters.mirai_httpflooding_1_4_dec_filter(data_df)
        elif "mirai-hostbruteforce-1-dec.pcap" in filename or "mirai-hostbruteforce-3-dec.pcap" in filename or "mirai-hostbruteforce-5-dec.pcap" in filename:
            data_labelled = data_filters.mirai_hostbruteforce_1_3_n_5_dec_filter(data_df)
        elif "mirai-hostbruteforce-2-dec.pcap" in filename or "mirai-hostbruteforce-4-dec.pcap" in filename:
            data_labelled = data_filters.mirai_hostbruteforce_2_n_4_dec_filter(data_df)
        else:
            # If no specific filter matches, use the original data.
            data_labelled = data_df

        # Save the labelled CSV to the destination folder.
        data_labelled.to_csv(dest_csv, index=False, header=True, mode='w')
        logger.info(f"{filename} converted and saved to {dest_csv}")
        print(f"{filename} converted and saved to {dest_csv}")
    except Exception as e:
        logger.warning(f"Error converting file {filename}: {e}")
        print(f"An error occurred with file '{filename}':", e)

    return pd.read_csv(dest_csv)