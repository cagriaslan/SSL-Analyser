import argparse
import json
import subprocess
import os

"""argument parsing section"""
ap = argparse.ArgumentParser()
ap.add_argument("-f", "--input", required=True, help="Input file path that will be parsed.")
ap.add_argument("-o", "--output", required=True, help="Output file name to write results into a CSV file.")
ap.add_argument("-i", "--install", action='store_true', help="Install required libraries for sslyze.")
ap.add_argument("-k", "--keep", action='store_true', help="Keep unparsed sslyze result file .")
args = vars(ap.parse_args())
"""end of argument parsing section"""


def sslyze_starter():
    if args["install"]:
        subprocess.run(["pip3", "install", "upgrade", "setuptools"])
        subprocess.run(["pip3", "install", "upgrade", "sslyze"])
    else:
        pass

    os.system(
        "python3 -m sslyze --regular --targets_in=" + args['input'] + " --json_out=" + args["input"].split(".")[0] +
        ".json --heartbleed --slow_connection")


class sslyze_parsing:

    def __init__(self, dictionary, *param):
        self.dictionary = dictionary
        self.param = param

    def get_field(self, *param):
        if len(self.param) == 2:
            try:
                return self.dictionary[self.param[0]][self.param[1]]
            except KeyError:
                return None
        elif len(self.param) == 3:
            try:
                return self.dictionary[self.param[0]][self.param[1]][self.param[2]]
            except KeyError:
                return None

    def sslyze_parser(self):
        """A json file should be provided"""
        with open(args["input"].split(".")[0] + ".json", "r", encoding="UTF-8") as fp:
            sslyze_json = json.load(fp)

        header = "Hostname, IP, Heartbleed, CCS Injection, Robot Attack, Downgrade Attack, " \
                 "Client Oriented Renegotiation, Secure Renegotiation\n"
        result = header
        for scan_result in sslyze_json["server_scan_results"]:
            # Known vulnerabilities check is_vulnerable_to_heartbleed = scan_result["scan_commands_results"]
            # ["heartbleed"]["is_vulnerable_to_heartbleed"]

            is_vulnerable_to_heartbleed = self.get_field(scan_result, "scan_commands_results", "heartbleed",
                                                         "is_vulnerable_to_heartbleed")
            is_vulnerable_to_ccs_injection = self.get_field(scan_result, "scan_commands_results",
                                                            "openssl_ccs_injection",
                                                            "is_vulnerable_to_ccs_injection")
            is_vulnerable_to_robot_attack = self.get_field(scan_result, "scan_commands_results", "robot",
                                                           "robot_result")
            downgrade_attack = self.get_field(scan_result, "scan_commands_results", "tls_fallback_scsv",
                                              "supports_fallback_scsv")

            # Session Renegotiation
            client_oriented_reneg = self.get_field(scan_result, "scan_commands_results", "session_renegotiation",
                                                   "accepts_client_renegotiation")
            secure_reneg = self.get_field(scan_result, "scan_commands_results", "session_renegotiation",
                                          "supports_secure_renegotiation")

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

        with open(args["output"] + ".csv", "w", encoding="UTF-8") as fp:
            fp.write(result)


if __name__ == '__main__':
    sslyze_starter()
    sslyze_object = sslyze_parsing(args["input"], args["output"])
    sslyze_object.sslyze_parser()

    if args["keep"]:
        pass
    else:
        subprocess.run(["rm", os.getcwd() + "/" + args["input"].split(".")[0] + ".json"])

