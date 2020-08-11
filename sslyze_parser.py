import argparse
import sys  # check uninstalled library
import sslyze
import json
import subprocess
import os

"""argument parsing section"""
ap = argparse.ArgumentParser()
ap.add_argument("-f", "--input", required=True, help="Input file path that will be parsed.")
ap.add_argument("-o", "--output", required=True, help="Output file name to write results into a CSV file.")
# ap.add_argument("-i", "--install", action='store_true', help="Install required libraries for sslyze.")
ap.add_argument("-k", "--keep", action='store_true', help="Keep unparsed sslyze result file .")
args = vars(ap.parse_args())
"""end of argument parsing section"""

"""This part will be implemented in install_sslyze and calculate_results instead of here"""


# def sslyze_starter():
#     if args["install"]:
#     else:
#         pass
#
#     os.system(
#         "python3 -m sslyze --regular --targets_in=" + args['input'] + " --json_out=" + args["input"].split(".")[0] +
#         ".json --heartbleed --slow_connection")


def get_field(dictionary, *param):
    """This can be static method and doesn't need to be inside of the class"""
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


def check_sslyze():
    """check sslyze if it exists on the system"""
    return 'sslyze' in sys.modules


class SslyzeClass:
    def __init__(self, input_file, output_file):
        self.input_file = input_file
        self.subdomain_list = self.create_subdomain_list()
        self.output_file = output_file
        self.is_sslyze_present = check_sslyze()  # to check if sslyze is present on the system
        self.sslyze_result = {}  # sslyze result to be used to create the csv file
        """
        dict structure:
        "subdomain_name": [features]
        "subdomain_name": [features]
        """

    def create_subdomain_list(self):
        """Input is assumed to be the output from subdomain enumeration."""
        temp_list = []
        with open(self.input_file, "r") as fp:
            for line in fp:
                temp_list.append(line.split(",")[0])
        return temp_list

    def install_ssylze(self):
        if self.is_sslyze_present:
            print("Already installed.")
            return
        else:
            subprocess.run(["pip3", "install", "setuptools"])
            subprocess.run(["pip3", "install", "sslyze"])

    def write_to_csv(self):
        """Write to csv using self.sslyze_result"""

    def write_to_json(self):
        """Write raw sslyze output to json just before parsing"""

    def calculate_results(self):
        """Use sslyze library to implement the features below"""

        subdomains = ["autodiscover.tpao.gov.tr",
                      "mail.tpao.gov.tr",
                      "mailhost.tpao.gov.tr",
                      "odeme.tpao.gov.tr"]

        for host in subdomains:
            server_location = sslyze.ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(hostname=host)

        try:
            server_info = sslyze.ServerConnectivityTester.perform(server_location)

        except ConnectionError as e:
            print(f"Error connecting to {server_location}: {e.error_message}")
            return

        scanner = sslyze.Scanner()
        server_scan_req = sslyze.ServerScanRequest(server_info=server_info,
                                                   scan_commands={sslyze.ScanCommand.CERTIFICATE_INFO,
                                                                  sslyze.ScanCommand.HEARTBLEED,
                                                                  sslyze.ScanCommand.ROBOT,
                                                                  sslyze.ScanCommand.SSL_2_0_CIPHER_SUITES,
                                                                  sslyze.ScanCommand.SSL_3_0_CIPHER_SUITES,
                                                                  sslyze.ScanCommand.OPENSSL_CCS_INJECTION,
                                                                  sslyze.ScanCommand.SESSION_RENEGOTIATION,
                                                                  sslyze.ScanCommand.TLS_1_0_CIPHER_SUITES,
                                                                  sslyze.ScanCommand.TLS_1_1_CIPHER_SUITES,
                                                                  sslyze.ScanCommand.TLS_1_2_CIPHER_SUITES,
                                                                  sslyze.ScanCommand.TLS_1_3_CIPHER_SUITES,
                                                                  sslyze.ScanCommand.SESSION_RESUMPTION,
                                                                  sslyze.ScanCommand.TLS_COMPRESSION,
                                                                  sslyze.ScanCommand.TLS_FALLBACK_SCSV,
                                                                  })

        scanner.queue_scan(server_scan_req)

        for server_scan_result in scanner.get_results():
            print(f"\nResults for {server_scan_result.server_info.server_location.hostname}:")

        ssl2_result = server_scan_result.scan_commands_results[sslyze.ScanCommand.SSL_2_0_CIPHER_SUITES]
        print("\nAccepted cipher suites for SSL 2.0:")

        for accepted_cipher_suite in ssl2_result:  # in ssl2_result.accepted_cipher_suites:
            print(f"* {accepted_cipher_suite.cipher_suite.name}")

        certinfo_result = server_scan_result.scan_commands_results[sslyze.ScanCommand.CERTIFICATE_INFO]
        print("\nCertificate info:")
        for cert_deployment in certinfo_result.certificate_deployments:
            print(f"Leaf certificate: \n{cert_deployment.received_certificate_chain_as_pem[0]}")


        # header = "Hostname, IP, Heartbleed, CCS Injection, Robot Attack, Downgrade Attack, " \
        #          "Client Oriented Renegotiation, Secure Renegotiation\n"
        # result = header
        # for scan_result in sslyze_json["server_scan_results"]:
        #     # Known vulnerabilities check is_vulnerable_to_heartbleed = scan_result["scan_commands_results"]
        #     # ["heartbleed"]["is_vulnerable_to_heartbleed"]
        #
        #     is_vulnerable_to_heartbleed = self.get_field(scan_result, "scan_commands_results", "heartbleed",
        #                                                  "is_vulnerable_to_heartbleed")
        #     is_vulnerable_to_ccs_injection = self.get_field(scan_result, "scan_commands_results",
        #                                                     "openssl_ccs_injection",
        #                                                     "is_vulnerable_to_ccs_injection")
        #     is_vulnerable_to_robot_attack = self.get_field(scan_result, "scan_commands_results", "robot",
        #                                                    "robot_result")
        #     downgrade_attack = self.get_field(scan_result, "scan_commands_results", "tls_fallback_scsv",
        #                                       "supports_fallback_scsv")
        #
        #     # Session Renegotiation
        #     client_oriented_reneg = self.get_field(scan_result, "scan_commands_results", "session_renegotiation",
        #                                            "accepts_client_renegotiation")
        #     secure_reneg = self.get_field(scan_result, "scan_commands_results", "session_renegotiation",
        #                                   "supports_secure_renegotiation")
        #
        #     # Weak cipher support should be implemented
        #
        #     # Hostname and IP
        #     hostname = scan_result["server_info"]["server_location"]["hostname"]
        #     ip = scan_result["server_info"]["server_location"]["ip_address"]
        #
        #     entry = "{},{},{},{},{},{},{},{}\n".format(hostname,
        #                                                ip,
        #                                                "Vulnerable to Heartbleed" if is_vulnerable_to_heartbleed else "Not vulnerable to Heartbleed",
        #                                                "Vulnerable to CCS injection" if is_vulnerable_to_ccs_injection else "Not vulnerable to OpenSSL CCS injection",
        #                                                is_vulnerable_to_robot_attack,
        #                                                "OK - Supported" if downgrade_attack else "Downgrade Attack Possible",
        #                                                "VULNERABLE - Server honors client-initiated renegotiations" if client_oriented_reneg else "Not vulnerable",
        #                                                "OK - Supported" if secure_reneg else "Not Supported")
        #     result = result + entry
        #
        # with open(args["output"] + ".csv", "w", encoding="UTF-8") as fp:
        #     fp.write(result)


if __name__ == '__main__':
    sslyze_obj = SslyzeClass(args["input"], args["output"])
    sslyze_obj.install_ssylze()
    sslyze_obj.calculate_results()
    if args["keep"]:
        sslyze_obj.write_to_json()
    else:
        pass
    sslyze_obj.write_to_csv()

    """
    sslyze_starter()
    sslyze_object = sslyze_parsing(args["input"], args["output"])
    sslyze_object.sslyze_parser()

    if args["keep"]:
        pass
    else:
        subprocess.run(["rm", os.getcwd() + "/" + args["input"].split(".")[0] + ".json"])
    """
