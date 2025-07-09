
import ipaddress
from pandas import DataFrame


def check_ip_range(x, ip_range):
    if isinstance(x, str):
        return ipaddress.IPv4Address(x) in ipaddress.IPv4Network(ip_range)
    else:
        return False


def sample_filter_fn(data: DataFrame) -> DataFrame:
    filters = [(None,None,None),(None,None,None)]

    data['label'] = 'normal'
    for filter_condition, label, rng in filters:
        data[:rng].loc[filter_condition.values, 'label'] = label

    return data


def benign_dec(data: DataFrame):
    data['label'] = 'normal'

    return data


def mitm_arpspoofing_1_3_dec_filter(data: DataFrame) -> DataFrame:

    filter_condition = (
        (data['eth_addr'] == 'f0:18:98:5e:ff:9f') &
        (
            (
                ((data['ip_src'] == '192.168.0.16') & (data['ip_dst'] == '192.168.0.13')) |
                ((data['ip_src'] == '192.168.0.13') & (data['ip_dst'] == '192.168.0.16'))
            ) &
            (~data['icmp_type'].apply(lambda x: bool(x))).any() &
            data['tcp_']
        ) |
        (
            (data['arp_src_hw_mac'] == 'f0:18:98:5e:ff:9f') &
            (
                (data['arp_dst_hw_mac'] == 'bc:1c:81:4b:ae:ba') |
                (data['arp_dst_hw_mac'] == '48:4b:aa:2c:d8:f9')
            )
        )
    )
    filters = [(filter_condition, 'mitm_arpspoofing', None)]

    data['label'] = 'normal'
    for filter_condition, label, rng in filters:
        data[:rng].loc[filter_condition.values, 'label'] = label

    return data



def mitm_arpspoofing_4_6_dec_filter(data: DataFrame) -> DataFrame:

    filter_condition = (
        (data['eth_addr'] == 'f0:18:98:5e:ff:9f') &
        (
            (
                (data['ip_addr'] == '192.168.0.24') &
                (~data['icmp_type'].apply(lambda x: bool(x))).any() &
                data['tcp_']
            ) |
            (
                (data['arp_src_hw_mac'] == 'f0:18:98:5e:ff:9f') &
                (
                    (data['arp_dst_hw_mac'] == '04:32:f4:45:17:b3') |
                    (data['arp_dst_hw_mac'] == '88:36:6c:d7:1c:56')
                )
            )
        )
    )
    filters = [(filter_condition, 'mitm_arpspoofing', None)]

    data['label'] = 'normal'
    for filter_condition, label, rng in filters:
        data[:rng].loc[filter_condition.values, 'label'] = label

    return data


def dos_synflooding_1_2_dec_filter(data: DataFrame) -> DataFrame:
    filter_condition = (
        (data['ip_src'].apply(lambda x: check_ip_range(x,'222.0.0.0/8'))) &
        (data['tcp_flags_syn'] == 1) &
        (data['ip_dst'] == '192.168.0.13') &
        (data['tcp_dstport'] == 554) &
        data['tcp_']
    )
    filters = [(filter_condition, 'dos_synflooding', None)]

    data['label'] = 'normal'
    for filter_condition, label, rng in filters:
        data[:rng].loc[filter_condition.values, 'label'] = label

    return data


def dos_synflooding_3_dec_filter(data: DataFrame) -> DataFrame:
    filter_condition = (
        (data['ip_src'].apply(lambda x: check_ip_range(x,'111.0.0.0/8'))) &
        (data['tcp_flags_syn'] == 1) &
        (data['ip_dst'] == '192.168.0.13') &
        (data['tcp_dstport'] == 554) &
        data['tcp_']
    )
    filters = [(filter_condition, 'dos_synflooding', None)]

    data['label'] = 'normal'
    for filter_condition, label, rng in filters:
        data[:rng].loc[filter_condition.values, 'label'] = label

    return data


def dos_synflooding_4_6_dec_filter(data: DataFrame) -> DataFrame:
    filter_condition = (
        (data['ip_dst'] == '192.168.0.24') &
        (data['tcp_flags_syn'] == 1) &
        (data['ip_src'].apply(lambda x: check_ip_range(x,'111.0.0.0/8'))) &
        data['tcp_'] &
        (data['tcp_dstport'] == 19604)
    )
    filters = [(filter_condition, 'dos_synflooding', None)]

    data['label'] = 'normal'
    for filter_condition, label, rng in filters:
        data[:rng].loc[filter_condition.values, 'label'] = label

    return data


def scan_hostport_1_dec_filter(data: DataFrame) -> DataFrame:
    scan_hostport_1_dec_1 = (
        (data['eth_src'] == 'f0:18:98:5e:ff:9f') &
        (data['arp_hw_type']) &
        (data['eth_dst'] == 'ff:ff:ff:ff:ff:ff')
    )[:12999]


    scan_hostport_1_dec_2 = (
        (data['ip_src'] == '192.168.0.15') &
        (data['ip_dst'] == '192.168.0.13') &
        (
            ((data['tcp_flags_syn'] == 1) & (data['tcp_window_size'] == 1024)) |
            (data['tcp_flags_reset'] == 1)
        )
    )
    filters = [(scan_hostport_1_dec_1, 'scanning_host', 12999), 
            (scan_hostport_1_dec_2, 'scanning_port', None)]

    data['label'] = 'normal'
    for filter_condition, label, rng in filters:
        data[:rng].loc[filter_condition.values, 'label'] = label

    return data


def scan_hostport_2_dec_filter(data: DataFrame) -> DataFrame:
    scan_hostport_2_dec_1 = (
        (data['eth_src'] == 'f0:18:98:5e:ff:9f') &
        (data['arp_hw_type']) &
        (data['eth_dst'] == 'ff:ff:ff:ff:ff:ff')
    )[:14499]

    # Scanning -- Port Scanning
    scan_hostport_2_dec_2 = (
        (data['ip_src'] == '192.168.0.15') &
        (data['ip_dst'] == '192.168.0.13') &
        (
            ((data['tcp_flags_syn'] == 1) & (data['tcp_window_size'] == 1024)) |
            (data['tcp_flags_reset'] == 1)
        )
    )
    filters = [(scan_hostport_2_dec_1, 'scanning_host', 14499), 
            (scan_hostport_2_dec_2, 'scanning_port', None)]

    data['label'] = 'normal'
    for filter_condition, label, rng in filters:
        data[:rng].loc[filter_condition.values, 'label'] = label

    return data


def scan_hostport_3_dec_filter(data: DataFrame) -> DataFrame:
    scan_hostport_3_dec_1 = (
        (data['eth_src'] == 'f0:18:98:5e:ff:9f') &
        (data['arp_hw_type']) &
        (data['eth_dst'] == 'ff:ff:ff:ff:ff:ff')
    )[:1999]

    # Scanning -- Port Scanning
    scan_hostport_3_dec_2 = (
        (data['ip_src'] == '192.168.0.15') &
        (data['ip_dst'] == '192.168.0.13') &
        (
            ((data['tcp_flags_syn'] == 1) & (data['tcp_window_size'] == 1024)) |
            (data['tcp_flags_reset'] == 1)
        )
    )
    filters = [(scan_hostport_3_dec_1, 'scanning_host', 1999), 
            (scan_hostport_3_dec_2, 'scanning_port', None)]

    data['label'] = 'normal'
    for filter_condition, label, rng in filters:
        data[:rng].loc[filter_condition.values, 'label'] = label

    return data


def scan_hostport_4_dec_filter(data: DataFrame) -> DataFrame:
    scan_hostport_4_dec_1 = (
        (data['eth_src'] == 'f0:18:98:5e:ff:9f') &
        (data['arp_hw_type']) &
        (data['eth_dst'] == 'ff:ff:ff:ff:ff:ff')
    )[:3999]

    scan_hostport_4_dec_2 = (
        (data['ip_src'] == '192.168.0.15') &
        (data['ip_dst'] == '192.168.0.24') &
        (
            ((data['tcp_flags_syn'] == 1) & (data['tcp_window_size'] == 1024)) |
            (data['tcp_flags_reset'] == 1)
        )
    )
    filters = [(scan_hostport_4_dec_1, 'scanning_host', 3999), 
            (scan_hostport_4_dec_2, 'scanning_port', None)]

    data['label'] = 'normal'
    for filter_condition, label, rng in filters:
        data[:rng].loc[filter_condition.values, 'label'] = label

    return data



def scan_hostport_5_dec_filter(data: DataFrame) -> DataFrame:
    scan_hostport_5_dec_1 = (
        (data['eth_src'] == 'f0:18:98:5e:ff:9f') &
        (data['arp_hw_type']) &
        (data['eth_dst'] == 'ff:ff:ff:ff:ff:ff')
    )[:1299]

    # Scanning -- Port Scanning
    scan_hostport_5_dec_2 = (
        (data['ip_src'] == '192.168.0.15') &
        (data['ip_dst'] == '192.168.0.24') &
        (
            ((data['tcp_flags_syn'] == 1) & (data['tcp_window_size'] == 1024)) |
            (data['tcp_flags_reset'] == 1)
        )
    )
    filters = [(scan_hostport_5_dec_1, 'scanning_host', 1299), 
            (scan_hostport_5_dec_2, 'scanning_port', None)]

    data['label'] = 'normal'
    for filter_condition, label, rng in filters:
        data[:rng].loc[filter_condition.values, 'label'] = label

    return data


def scan_hostport_6_dec_filter(data: DataFrame) -> DataFrame:
    scan_hostport_6_dec_1 = (
        (data['eth_src'] == 'f0:18:98:5e:ff:9f') &
        (data['arp_hw_type']) &
        (data['eth_dst'] == 'ff:ff:ff:ff:ff:ff')
    )[:999]


    scan_hostport_6_dec_2 = (
        (data['ip_src'] == '192.168.0.15') &
        (data['ip_dst'] == '192.168.0.24') &
        (
            ((data['tcp_flags_syn'] == 1) & (data['tcp_window_size'] == 1024)) |
            (data['tcp_flags_reset'] == 1)
        )
    )
    filters = [(scan_hostport_6_dec_1, 'scanning_host', 999), 
            (scan_hostport_6_dec_2, 'scanning_port', None)]

    data['label'] = 'normal'
    for filter_condition, label, rng in filters:
        data[:rng].loc[filter_condition.values, 'label'] = label

    return data


def scan_portos_1_3_dec_filter(data: DataFrame) -> DataFrame:
    scan_portos_1_dec_1 = (
        (data['ip_src'] == '192.168.0.15') &
        (data['ip_dst'] == '192.168.0.13') &
        (
            ((data['tcp_flags_syn'] == 1) & (data['tcp_window_size'] == 1024)) |
            (data['tcp_flags_reset'] == 1)
        )
    )

    # Scanning -- OS Scanning
    scan_portos_1_dec_2 = (
        (data['ip_src'] == '192.168.0.15') &
        (data['ip_dst'] == '192.168.0.13') &
        ((~data['icmp_type'].apply(lambda x: bool(x))).any()) &
        ~((data['ip_src'] == '192.168.0.15') &
        (data['ip_dst'] == '192.168.0.13') &
        (((data['tcp_flags_syn'] == 1) & (data['tcp_window_size'] == 1024)) |
        (data['tcp_flags_reset'] == 1)))
    )
    filters = [(scan_portos_1_dec_1, 'scanning_port', None), 
               (scan_portos_1_dec_2, 'scanning_os', None)]

    data['label'] = 'normal'
    for filter_condition, label, rng in filters:
        data[:rng].loc[filter_condition.values, 'label'] = label

    return data


def scan_portos_4_6_dec_filter(data: DataFrame) -> DataFrame:
    scan_portos_1_dec_1 = (
        (data['ip_src'] == '192.168.0.15') &
        (data['ip_dst'] == '192.168.0.24') &
        (
            ((data['tcp_flags_syn'] == 1) & (data['tcp_window_size'] == 1024)) |
            (data['tcp_flags_reset'] == 1)
        )
    )


    scan_portos_1_dec_2 = (
        (data['ip_src'] == '192.168.0.15') &
        (data['ip_dst'] == '192.168.0.24') &
        ((~data['icmp_type'].apply(lambda x: bool(x))).any()) &
        ~((data['ip_src'] == '192.168.0.15') &
        (data['ip_dst'] == '192.168.0.24') &
        (((data['tcp_flags_syn'] == 1) & (data['tcp_window_size'] == 1024)) |
        (data['tcp_flags_reset'] == 1)))
    )
    filters = [(scan_portos_1_dec_1, 'scanning_port', None), 
               (scan_portos_1_dec_2, 'scanning_os', None)]

    data['label'] = 'normal'
    for filter_condition, label, rng in filters:
        data[:rng].loc[filter_condition.values, 'label'] = label

    return data


def mirai_udpflooding_1_4_dec_filter(data: DataFrame) -> DataFrame:

    filter_condition = (data['ip_dst'] == '210.89.164.90')

    filters = [(filter_condition, 'mirai_udpflooding', None)]

    data['label'] = 'normal'
    for filter_condition, label, rng in filters:
        data[:rng].loc[filter_condition.values, 'label'] = label

    return data


def mirai_ackflooding_1_4_dec_filter(data: DataFrame) -> DataFrame:

    filter_condition = (data['ip_dst'] == '210.89.164.90')

    filters = [(filter_condition, 'mirai_ackflooding', None)]

    data['label'] = 'normal'
    for filter_condition, label, rng in filters:
        data[:rng].loc[filter_condition.values, 'label'] = label

    return data


def mirai_httpflooding_1_4_dec_filter(data: DataFrame) -> DataFrame:

    filter_condition = (data['ip_dst'] == '210.89.164.90')

    filters = [(filter_condition, 'mirai_httpflooding', None)]

    data['label'] = 'normal'
    for filter_condition, label, rng in filters:
        data[:rng].loc[filter_condition.values, 'label'] = label

    return data




def mirai_hostbruteforce_1_3_n_5_dec_filter(data: DataFrame) -> DataFrame:
    mirai_hostbruteforce_1_dec_1 = (
        (data['arp_dst_proto_ipv4'].apply(lambda x: check_ip_range(x,'192.168.0.0/24'))) &
        (data['arp_src_proto_ipv4'] == '192.168.0.13') &
        (data['eth_dst'] == 'ff:ff:ff:ff:ff:ff')
    )


    mirai_hostbruteforce_1_dec_2 = (
        (data['tcp_dstport'] == 23) &
        (data['ip_src'] == '192.168.0.13')
    )
    filters = [(mirai_hostbruteforce_1_dec_1, 'host_discovery', None), 
               (mirai_hostbruteforce_1_dec_2, 'telnet_bruteforce', None)]

    data['label'] = 'normal'
    for filter_condition, label, rng in filters:
        data[:rng].loc[filter_condition.values, 'label'] = label

    return data


def mirai_hostbruteforce_2_n_4_dec_filter(data: DataFrame) -> DataFrame:
    mirai_hostbruteforce_1_dec_1 = (
        (data['arp_dst_proto_ipv4'].apply(lambda x: check_ip_range(x,'192.168.0.0/24'))) &
        (data['arp_src_proto_ipv4'] == '192.168.0.24') &
        (data['eth_dst'] == 'ff:ff:ff:ff:ff:ff')
    )


    mirai_hostbruteforce_1_dec_2 = (
        (data['tcp_dstport'] == 23) &
        (data['ip_src'] == '192.168.0.24')
    )
    filters = [(mirai_hostbruteforce_1_dec_1, 'host_discovery', None), 
               (mirai_hostbruteforce_1_dec_2, 'telnet_bruteforce', None)]

    data['label'] = 'normal'
    for filter_condition, label, rng in filters:
        data[:rng].loc[filter_condition.values, 'label'] = label

    return data
