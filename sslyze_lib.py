import sslyze
import json
from dataclasses import asdict


def scann():
    servers_to_scan = []

    # sub = ['odeme.tpao.gov.tr',
    #        'mail.tpao.gov.tr',
    #        'mailhost.tpao.gov.tr',
    #        'autodiscover.tpao.gov.tr'
    #        ]
    sub = ['odeme.tpao.gov.tr']

    for hostname in sub:
        server_location = sslyze.ServerNetworkLocationViaDirectConnection.with_ip_address_lookup(hostname, 443)
        try:
            server_info = sslyze.ServerConnectivityTester().perform(server_location)
            servers_to_scan.append(server_info)
        except ConnectionError as e:
            print(f"Error connecting to {server_location.hostname}:{server_location.port}: {e.error_message}")
            return

    scanner = sslyze.Scanner()

    # Then queue some scan commands for each server
    for server_info in servers_to_scan:
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

        server_scan_result_as_json = json.dumps(asdict(server_scan_result), cls=sslyze.JsonEncoder, indent=4)

    with open('blabla.json', 'w', encoding='UTF-8') as json_file:
        json_file.write(server_scan_result_as_json)


if __name__ == '__main__':
    scann()



