import 'package:simplify_commerce/simplify_commerce.dart';

import 'package:test/test.dart';

void main() {
  group('A group of tests', () {
    Simplify awesome = Simplify();

    setUp(() {
      // Additional setup goes here.
    });

    test('First Test', () async {
      // Call the create method with some test parameters
      var params = {'amount': 100, 'currency': 'USD'};
      var authArgs = ['apiKey', 'apiSecret'];
      var result = await awesome.payment.create(params, authArgs);

      expect(result, isTrue);
    });
  });
}
