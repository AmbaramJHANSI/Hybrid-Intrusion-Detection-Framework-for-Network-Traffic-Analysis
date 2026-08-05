import pandas as pd
import os

COLUMNS = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count",
    "dst_host_srv_count","dst_host_same_srv_rate",
    "dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate",
    "dst_host_srv_serror_rate","dst_host_rerror_rate",
    "dst_host_srv_rerror_rate","class","difficulty"
]

def convert(input_path, output_path):
    print(f"\nReading: {input_path}")

    df = pd.read_csv(
        input_path,
        header=None,
        sep=",",
        engine="python",
        dtype=str
    )

    print("Raw shape:", df.shape)

    if df.shape[1] != 43:
        raise ValueError(f"Expected 43 columns, got {df.shape[1]}")

    df.columns = COLUMNS

    # Drop difficulty
    df.drop(columns=["difficulty"], inplace=True)

    df.to_csv(output_path, index=False)

    print(f"Written: {output_path}")
    print("Final shape:", df.shape)


if __name__ == "__main__":
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DATASET_DIR = os.path.join(BASE_DIR, "dataset")

    convert(
        os.path.join(DATASET_DIR, "KDDTrain+.txt"),
        os.path.join(DATASET_DIR, "KDDTrain+.csv")
    )

    convert(
        os.path.join(DATASET_DIR, "KDDTest+.txt"),
        os.path.join(DATASET_DIR, "KDDTest+.csv")
    )

    convert(
        os.path.join(DATASET_DIR, "KDDTest-21.txt"),
        os.path.join(DATASET_DIR, "KDDTest-21.csv")
    )
