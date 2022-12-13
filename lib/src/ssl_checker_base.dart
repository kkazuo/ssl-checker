/*
Copyright 2022 Koga Kazuo (koga.kazuo@gmail.com)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 */

import 'dart:io';

/// Result of sslChecker()
class SslCheckResult {
  SslCheckResult._(
    this._certificate,
    this._valid,
    this._daysRemaining,
    this._subject,
  );

  final X509Certificate? _certificate;
  final bool _valid;
  final int _daysRemaining;
  final String? _subject;

  /// X509 certificate
  X509Certificate? get certificate => _certificate;

  /// true if this is valid.
  bool get valid => _valid;

  /// number of days remainings.
  int get daysRemaining => _daysRemaining;

  /// Certificate subject common name.
  String? get subject => _subject;

  @override
  String toString() {
    return 'valid=$valid, daysRemaining=$daysRemaining,'
        ' subject=$subject,'
        ' start=${certificate?.startValidity},'
        ' end=${certificate?.endValidity}';
  }

  /// Convert to JSON Object.
  dynamic toJson() => {
        'daysRemaining': daysRemaining,
        'subject': subject,
        'valid': valid,
        'validFrom': certificate?.startValidity.toIso8601String(),
        'validTo': certificate?.endValidity.toIso8601String(),
      };
}

int _daysRemaining(DateTime end) {
  final d = end.difference(DateTime.now());
  return d.inDays;
}

String? _commonName(String subject) {
  final idx = subject.indexOf('/CN=');
  if (0 <= idx) {
    return subject.substring(idx + 4);
  }
  return null;
}

/// Check certificate validity of host.
Future<SslCheckResult> sslChecker(
  String hostname, {
  int port = HttpClient.defaultHttpsPort,
  String method = 'HEAD',
  bool ignoreException = true,
}) async {
  var badCertificate = false;
  final client = HttpClient()
    ..badCertificateCallback = (cert, host, port) {
      badCertificate = true;
      return true;
    }
    ..connectionTimeout = const Duration(seconds: 55);
  try {
    final uri = Uri(
      scheme: 'https',
      host: hostname,
      path: '/',
      port: port,
    );
    final req = await client.openUrl(method, uri);
    final res = await req.close();
    final cert = res.certificate;

    return SslCheckResult._(
      cert,
      !badCertificate,
      cert != null ? _daysRemaining(cert.endValidity) : 0,
      cert != null ? _commonName(cert.subject) : null,
    );
  } catch (e) {
    if (ignoreException) return SslCheckResult._(null, false, -1, null);
    rethrow;
  } finally {
    client.close();
  }
}
