import 'package:simplify_commerce/simplify_commerce.dart';

Map<String, dynamic> data = {
  'amount': 10,
  'currency': 'USD',
  'card': {
    'number': '',
    'expMonth': '',
    'expYear': '',
    'cvc': '',
    'name': '',
    'addressLine1': '',
    'addressLine2': '',
    'addressCity': '',
    'addressState': '',
    'addressZip': '',
    'addressCountry': '',
  }
};

// Instance of Payment
Simplify simplify = Simplify();

// calling the payment object

var payment = simplify.payment.create(data, publicKey);

// calling cardToken Object

var cardToken = simplify.card.create(data, publicKey);

// Set up the auth object with your public and private API keys

var publicKey = 'YOUR PUBLIC KEY';

void main() {
  var sol = simplify.payment.create(data, publicKey); //
  var c = simplify.card.create(data, publicKey); // generates a card Token
  print(sol);
  print(c);
}
