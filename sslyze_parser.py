import argparse
import json


def get_field(dictionary, *param):
    if len(param) == 2:
        try:
            return dictionary[param[0]][param[1]]
        except KeyError:
            return None
    elif len(param) == 3:
        try:
            return dictionary[param[0]][param[1]][param[2]]
        except KeyError:
            return None


def sslyze_parser(file_name):
    """A json file should be provided"""
    with open(file_name, "r", encoding="UTF-8") as fp:
        sslyze_json = json.load(fp)

    header = "Hostname, IP, Heartbleed, CCS Injection, Robot Attack, Downgrade Attack, " \
             "Client Oriented Renegotiation, Secure Renegotiation\n"
    result = header
    for scan_result in sslyze_json["server_scan_results"]:
        # Known vulnerabilities check
        # is_vulnerable_to_heartbleed = scan_result["scan_commands_results"]["heartbleed"]["is_vulnerable_to_heartbleed"]
        is_vulnerable_to_heartbleed = get_field(scan_result, "scan_commands_results", "heartbleed", "is_vulnerable_to_heartbleed")
        is_vulnerable_to_ccs_injection = get_field(scan_result, "scan_commands_results", "openssl_ccs_injection", "is_vulnerable_to_ccs_injection")
        is_vulnerable_to_robot_attack = get_field(scan_result, "scan_commands_results", "robot", "robot_result")
        downgrade_attack = get_field(scan_result, "scan_commands_results", "tls_fallback_scsv", "supports_fallback_scsv")

        # Session Renegotiation
        client_oriented_reneg = get_field(scan_result, "scan_commands_results", "session_renegotiation", "accepts_client_renegotiation")
        secure_reneg = get_field(scan_result, "scan_commands_results", "session_renegotiation", "supports_secure_renegotiation")

        # Weak cipher support should be implemented

        # Hostname and IP
        hostname = scan_result["server_info"]["server_location"]["hostname"]
        ip = scan_result["server_info"]["server_location"]["ip_address"]

        entry = "{},{},{},{},{},{},{},{}\n".format(hostname,
                                                   ip,
                                                   "Vulnerable to Heartbleed" if is_vulnerable_to_heartbleed else "Not vulnerable to Heartbleed",
                                                   "Vulnerable to CCS injection" if is_vulnerable_to_ccs_injection else "Not vulnerable to OpenSSL CCS injection",
                                                   is_vulnerable_to_robot_attack,
                                                   "OK - Supported" if downgrade_attack else "Downgrade Attack Possible",
                                                   "VULNERABLE - Server honors client-initiated renegotiations" if client_oriented_reneg else "Not vulnerable",
                                                   "OK - Supported" if secure_reneg else "Not Supported")
        result = result + entry

    with open(file_name.split(".")[0] + ".csv", "w", encoding="UTF-8") as fp:
        fp.write(result)


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument("-f", "--filename", required=True, help="sslyze output file to parse")
    args = ap.parse_args()

    sslyze_parser(args.filename)
