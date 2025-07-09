
```
├── README.md
├── brokerServer
│   ├── broker_server.py
│   └── templates
│       └── login.html
├── data
│   ├── external
│   ├── interim
│   ├── labelled
│   ├── processed
│   └── raw
├── mitigation
│   └── mitigation.py
├── models
│   ├── metrics.json
│   ├── xgb_model.bin
│   └── xgb_model.joblib
├── networks
│   ├── logs
│   │   └── pipeline.log
│   ├── network1
│   │   ├── network1.py
│   │   └── network_id.json
│   └── network2
│       ├── network2.py
│       └── network_id.json
├── requirements.txt
├── run.sh
├── server
│   ├── __pycache__
│   │   └── server.cpython-312.pyc
│   ├── server.py
│   ├── static
│   └── templates
│       ├── login.html
│       ├── main_dashboard.html
│       └── network_dashboard.html
├── setup.py
├── src
│   ├── __init__.py
│   ├── __pycache__
│   │   └── __init__.cpython-312.pyc
│   ├── data
│   │   ├── __init__.py
│   │   ├── __pycache__
│   │   │   ├── __init__.cpython-312.pyc
│   │   │   ├── data_filters.cpython-312.pyc
│   │   │   ├── load_n_filter.cpython-312.pyc
│   │   │   └── pcap_to_csv.cpython-312.pyc
│   │   ├── data_filters.py
│   │   ├── load_n_filter.py
│   │   ├── packet_streamer.py
│   │   └── pcap_to_csv.py
│   ├── features
│   │   ├── __init__.py
│   │   ├── __pycache__
│   │   │   ├── __init__.cpython-312.pyc
│   │   │   └── build_features.cpython-312.pyc
│   │   ├── build_features.py
│   │   └── scaler.pkl
│   ├── models
│   │   ├── __init__.py
│   │   └── train_model.py
│   └── utils
│       ├── __init__.py
│       ├── __pycache__
│       │   ├── __init__.cpython-312.pyc
│       │   └── pipeline_log_config.cpython-312.pyc
│       ├── backend_log_config.py
│       ├── frontend_log_config.py
│       └── pipeline_log_config.py
├── src.egg-info
│   ├── PKG-INFO
│   ├── SOURCES.txt
│   ├── dependency_links.txt
│   └── top_level.txt
├── temp
└── testData
    └── dos-synflooding-4-dec.csv
```