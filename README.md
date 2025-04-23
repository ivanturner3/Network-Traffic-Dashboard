# Network Traffic Dashboard

A real-time network traffic analysis dashboard built with Python, Scapy, and Streamlit.

## Features

- Real-time packet capture and analysis
- Visualization of network traffic patterns
- Protocol distribution analysis
- Traffic volume monitoring
- Automatic interface detection

## Requirements

- Python 3.8+
- Scapy
- Streamlit
- Pandas
- Plotly

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/YOUR_USERNAME/network-dashboard.git
   cd network-dashboard
   ```

2. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

3. Run the dashboard:
   ```
   streamlit run dashboard.py
   ```

## Usage

The dashboard automatically detects your network interface and begins capturing packets. The interface shows:

- Total packets captured
- Protocol distribution
- Traffic volume over time
- Recent packet details

## Note

This application requires administrator privileges to capture network packets. On Windows, you may need to run as administrator. On Linux/Mac, you may need to use sudo.

## License

[MIT License](LICENSE)