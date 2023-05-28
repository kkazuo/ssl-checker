import 'package:ssl_checker/ssl_checker.dart';
import 'package:test/test.dart';

void main() {
  group('A group of tests', () {
    setUp(() {
      // Additional setup goes here.
    });

    test('First Test', () async {
      var r = await sslChecker('expired.badssl.com');
      expect(r.valid, false);
      expect(r.daysRemaining, (int i) => i < 0);

      r = await sslChecker('sha256.badssl.com');
      expect(r.valid, true);
      expect(r.daysRemaining, (int i) => i > 0);

      r = await sslChecker('tls-v1-2.badssl.com', port: 1012);
      expect(r.valid, true);
      expect(r.daysRemaining, (int i) => i > 0);

      r = await sslChecker('[example:com]');
      expect(r.valid, false);
      expect(r.daysRemaining, -1);

      r = await sslChecker('example');
      expect(r.valid, false);
      expect(r.daysRemaining, -1);

      // You can not pass URL, must be HOSTNAME!!
      r = await sslChecker('https://www.google.com');
      expect(r.valid, false);
      expect(r.daysRemaining, -1);
    });
  });
}
