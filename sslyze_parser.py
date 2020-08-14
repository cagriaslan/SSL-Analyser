from dataclasses import asdict
import argparse
import sys  # check uninstalled library
import sslyze
import json
import subprocess

"""argument parsing section"""
ap = argparse.ArgumentParser()
ap.add_argument("-f", "--input", required=True, help="Input file path that will be parsed.")
ap.add_argument("-o", "--output", required=True, help="Output file name to write results into a CSV file.")
ap.add_argument("-k", "--keep", action='store_true', help="Keep unparsed sslyze result file .")
args = vars(ap.parse_args())
"""end of argument parsing section"""

"""This part will be implemented in install_sslyze and calculate_results instead of here"""


# def sslyze_starter():
#     if args["install"]:
#         subprocess.run(["pip3", "install", "upgrade", "setuptools"])
#         subprocess.run(["pip3", "install", "upgrade", "sslyze"])
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
        self.servers_to_scan = []  # server informations for sslyze scanning process
        self.scanner_get_result = {}
        self.sslyze_result = []  # server scan result as json

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
                temp_list.append(line.split(",")[0].strip())
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

        header = "Hostname, IP, Heartbleed, CCS Injection, Robot Attack, Downgrade Attack, " \
                 "Client Oriented Renegotiation, Secure Renegotiation\n"
        result = header
        # for scan_result in sslyze_json:
        # Known vulnerabilities check is_vulnerable_to_heartbleed = scan_result["scan_commands_results"]
        # ["heartbleed"]["is_vulnerable_to_heartbleed"]
        for each in self.sslyze_result:
            is_vulnerable_to_heartbleed = get_field(each, "scan_commands_results", "heartbleed", "is_vulnerable_to_heartbleed")
            is_vulnerable_to_ccs_injection = get_field(each, "scan_commands_results", "openssl_ccs_injection", "is_vulnerable_to_ccs_injection")
            is_vulnerable_to_robot_attack = get_field(each, "scan_commands_results", "robot", "robot_result")
            downgrade_attack = get_field(each, "scan_commands_results", "tls_fallback_scsv", "supports_fallback_scsv")

            # Session Renegotiation
            client_oriented_reneg = get_field(each, "scan_commands_results", "session_renegotiation", "accepts_client_renegotiation")
            secure_reneg = get_field(each, "scan_commands_results", "session_renegotiation", "supports_secure_renegotiation")

            # Weak cipher support should be implemented

            # Hostname and IP
            hostname = each["server_info"]["server_location"]["hostname"]
            ip = each["server_info"]["server_location"]["ip_address"]

            entry = "{},{},{},{},{},{},{},{}\n".format(hostname,
                                                       ip,
                                                       "Vulnerable to Heartbleed" if is_vulnerable_to_heartbleed else "Not vulnerable to Heartbleed",
                                                       "Vulnerable to CCS injection" if is_vulnerable_to_ccs_injection else "Not vulnerable to OpenSSL CCS injection",
                                                       is_vulnerable_to_robot_attack,
                                                       "OK - Supported" if downgrade_attack else "Downgrade Attack Possible",
                                                       "VULNERABLE - Server honors client-initiated renegotiations" if client_oriented_reneg else "Not vulnerable",
                                                       "OK - Supported" if secure_reneg else "Not Supported")
            result = result + entry
        # above code is from old snippet
        with open(self.output_file + ".csv", "w", encoding="UTF-8") as fp:
            fp.write(result)

    def write_to_json(self):
        """Write raw sslyze output to json just before parsing"""
        temp_dict = {"results": self.sslyze_result}
        with open(self.output_file + '.json', 'w', encoding='UTF-8') as json_file:
            json.dump(temp_dict, json_file, cls=sslyze.JsonEncoder, indent=4)

    def calculate_results(self):
        """Use sslyze library to implement the features below"""

        # server connection testing
        for hostname in self.subdomain_list:
            try:
                server_location = sslyze.ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(hostname, 443)
                try:
                    server_info = sslyze.ServerConnectivityTester().perform(server_location)
                    self.servers_to_scan.append(server_info)
                except ConnectionError as e:
                    print(f"Error connecting to {server_location.hostname}:{server_location.port}: {e.error_message}")
                    return
            except:
                print("Cannot resolve " + hostname + ", skipping..")
                pass

        scanner = sslyze.Scanner()

        # Queue scan commands for each server
        for server_info in self.servers_to_scan:
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

        self.scanner_get_result = scanner.get_results()
        # Then retrieve the result of the scan commands for each server
        for server_scan_result in scanner.get_results():
            print(f"\nResults for {server_scan_result.server_info.server_location.hostname}:")

            # Scan commands that were run with no errors
            try:
                ssl2_result = server_scan_result.scan_commands_results[sslyze.ScanCommand.SSL_2_0_CIPHER_SUITES]
                print("\nAccepted cipher suites for SSL 2.0:")
                for accepted_cipher_suite in ssl2_result.accepted_cipher_suites:
                    print(f"* {accepted_cipher_suite.cipher_suite.name}")
            except KeyError:
                pass

            try:
                ssl3_result = server_scan_result.scan_commands_results[sslyze.ScanCommand.SSL_3_0_CIPHER_SUITES]
                print("\nAccepted cipher suites for SSL 3.0:")
                for accepted_cipher_suite in ssl3_result.accepted_cipher_suites:
                    print(f"* {accepted_cipher_suite.cipher_suite.name}")
            except KeyError:
                pass

            try:
                tls1_0_result = server_scan_result.scan_commands_results[sslyze.ScanCommand.TLS_1_0_CIPHER_SUITES]
                print("\nAccepted cipher suites for TLS 1.0:")
                for accepted_cipher_suite in tls1_0_result.accepted_cipher_suites:
                    print(f"* {accepted_cipher_suite.cipher_suite.name}")
            except KeyError:
                pass

            try:
                tls1_1_result = server_scan_result.scan_commands_results[sslyze.ScanCommand.TLS_1_1_CIPHER_SUITES]
                print("\nAccepted cipher suites for TLS 1.1:")
                for accepted_cipher_suite in tls1_1_result.accepted_cipher_suites:
                    print(f"* {accepted_cipher_suite.cipher_suite.name}")
            except KeyError:
                pass

            try:
                tls1_2_result = server_scan_result.scan_commands_results[sslyze.ScanCommand.TLS_1_2_CIPHER_SUITES]
                print("\nAccepted cipher suites for TLS 1.2:")
                for accepted_cipher_suite in tls1_2_result.accepted_cipher_suites:
                    print(f"* {accepted_cipher_suite.cipher_suite.name}")
            except KeyError:
                pass

            try:
                tls1_3_result = server_scan_result.scan_commands_results[sslyze.ScanCommand.TLS_1_3_CIPHER_SUITES]
                print("\nAccepted cipher suites for TLS 1.3:")
                for accepted_cipher_suite in tls1_3_result.accepted_cipher_suites:
                    print(f"* {accepted_cipher_suite.cipher_suite.name}")
            except KeyError:
                pass

            try:
                heartbleed_result = server_scan_result.scan_commands_results[sslyze.ScanCommand.HEARTBLEED]
                print("\nResult for heartbleed:")
                print(f"*{str(heartbleed_result.is_vulnerable_to_heartbleed)}")
            except KeyError as e:
                print(e)

            try:
                robot_result = server_scan_result.scan_commands_results[sslyze.ScanCommand.ROBOT]
                print("\nResult for robot:")
                print(f"* {str(robot_result)}")
            except KeyError as e:
                print(e)

            try:
                openssl_css_result = server_scan_result.scan_commands_results[sslyze.ScanCommand.OPENSSL_CCS_INJECTION]
                print("\nResult for openssl:")
                print(f"* {str(openssl_css_result.is_vulnerable_to_ccs_injection)}")

            except KeyError as e:
                print(e)

            try:
                session_reneg = server_scan_result.scan_commands_results[sslyze.ScanCommand.SESSION_RENEGOTIATION]
                print("\nResult for session renegotiation:")
                print(f"* accepts client renegotitation: {str(session_reneg.accepts_client_renegotiation)} \n"
                      f"* supports_secure_renegotiation: {str(session_reneg.supports_secure_renegotiation)}")

            except KeyError as e:
                print(e)

            try:
                tls_compression_result = server_scan_result.scan_commands_results[sslyze.ScanCommand.TLS_COMPRESSION]
                print("\nResult for TLS Compression:")
                print(f"* {str(tls_compression_result.supports_compression)}")

            except KeyError as e:
                print(e)

            try:
                tls_fallback_result = server_scan_result.scan_commands_results[sslyze.ScanCommand.TLS_FALLBACK_SCSV]
                print("\nResult for TLS Fallback Downgrade Prevention:")
                print(f"* {str(tls_fallback_result.supports_fallback_scsv)}")

            except KeyError as e:
                print(e)

            try:
                # Scan commands that were run with errors
                for scan_command, error in server_scan_result.scan_commands_errors.items():
                    print(f"\nError when running {scan_command}:\n{error.exception_trace}")

            except TimeoutError as t:
                print(t)

            self.sslyze_result.append(asdict(server_scan_result))
            with open(server_scan_result.server_info.server_location.hostname + ".json", "w", encoding="UTF-8") as ff:
                ff.write(json.dumps(asdict(server_scan_result), cls=sslyze.JsonEncoder))


if __name__ == '__main__':
    sslyze_obj = SslyzeClass(args["input"], args["output"])
    sslyze_obj.install_ssylze()
    sslyze_obj.calculate_results()

    if args["keep"]:
        sslyze_obj.write_to_json()
        sslyze_obj.write_to_csv()
    else:
        sslyze_obj.write_to_csv()
