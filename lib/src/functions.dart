// ignore_for_file: non_constant_identifier_names, constant_identifier_names, unnecessary_null_comparison

import 'dart:convert';
import 'dart:core';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;

import 'package:simplify_commerce/src/constants.dart';

String? globalPublicKey;
String? globalPrivateKey;

// ################################################################################
// Constants
// ################################################################################

var HTTP_SUCCESS = 200;
var HTTP_REDIRECTED = 302;
var HTTP_UNAUTHORIZED = 401;
var HTTP_NOT_FOUND = 404;
var HTTP_NOT_ALLOWED = 405;
var HTTP_BAD_REQUEST = 400;

String HTTP_METHOD_POST = "POST";
String HTTP_METHOD_PUT = "PUT";
String HTTP_METHOD_GET = "GET";
String HTTP_METHOD_DELETE = "DELETE";

// global variable initialization
Constants cons = Constants();

// ################################################################
// BUILDERS
// ################################################################

String buildQueryString(Map<String, dynamic> criteria) {
  if (criteria == null) {
    return '';
  }

  final queryString = <String>[];
  if (criteria.containsKey('max')) {
    queryString.add('max=${criteria['max']}');
  }

  if (criteria.containsKey('offset')) {
    queryString.add('offset=${criteria['offset']}');
  }

  if (criteria.containsKey('sorting')) {
    criteria['sorting'].forEach((key, value) {
      queryString.add('sorting[$key]=${Uri.encodeComponent(value.toString())}');
    });
  }

  if (criteria.containsKey('filter')) {
    criteria['filter'].forEach((key, value) {
      queryString.add('filter[$key]=${Uri.encodeComponent(value.toString())}');
    });
  }

  return queryString.join('&');
}

handleHttpError(responseBody, responseCode) {
  if (responseCode == HTTP_REDIRECTED) {
    // this shouldn't happen - if it does it's our problem
    throw BadRequestError(
        "Unexpected response code returned from the API, have you got the correct URL?", responseCode, responseBody);
  } else if (responseCode == HTTP_BAD_REQUEST) {
    throw BadRequestError("Bad request", responseCode, responseBody);
  } else if (responseCode == HTTP_UNAUTHORIZED) {
    throw AuthenticationError("You are not authorized to make this request.  Are you using the correct API keys?",
        responseCode, responseBody);
  } else if (responseCode == HTTP_NOT_FOUND) {
    throw ObjectNotFoundError("Object not found", responseCode, responseBody);
  } else if (responseCode == HTTP_NOT_ALLOWED) {
    throw NotAllowedError("Operation not allowed", responseCode, responseBody);
  } else if (responseCode < 500) {
    throw BadRequestError("Bad request", responseCode, responseBody);
  } else {
    throw SysError("An unexpected error has been raised.  Looks like there's something wrong at our end.", responseCode,
        responseBody);
  }
}

// #################################################################################
// Authentication
// #################################################################################

class Auth {
  //   Authentication object.
  //  Holds authentication information used when accessing the API.

  //   public_key: Public key used to access the API.
  //   private_key: Private key used to access the API.
  //   access_token: OAuth token used to access the API.

  String? publicKey;

  Auth({this.publicKey}) {
    publicKey = globalPublicKey;
  }
}

class AccessToken {
  // OAuth access token.

  //       access_token: Access token used when making an API call authenticated using OAuth
  //       refresh_token: Token used when refreshing an access token.
  //       expires_in: Number of seconds from the time the token was created till it expires.
  String accessToken;
  String refreshToken;
  int expiresIn;

  AccessToken(this.accessToken, this.refreshToken, this.expiresIn);

  static Future<AccessToken> create(String authCode, String redirectUri, String authArgs) async {
    final props = {
      'grant_type': 'authorization_code',
      'code': authCode,
      'redirect_uri': redirectUri,
    };

    final h = await PaymentApi().sendAuthRequest(props, 'token', PaymentApi.createAuthObject(authArgs));
    return AccessToken(h['access_token'], h['refresh_token'], h['expires_in']);
  }

  Future refresh(String authArgs) async {
    // Refreshes an AccessToken object.  If successful the access_token, refresh_token and expires_in attributes are updated.

    // @param auth_args: an Authentication object used for the API call.  If no value is passed the global keys simplify.public_key and simplify.private_key are used.

    if (refreshToken == null) {
      throw IllegalArgumentError("Cannot refresh access token; refresh token is invalid.");
    }

    final props = {
      'grant_type': 'refresh_token',
      'refresh_token': refreshToken,
    };

    final h = await PaymentApi().sendAuthRequest(props, 'token', PaymentApi.createAuthObject(authArgs));
    accessToken = h['access_token'];
    refreshToken = h['refresh_token'];
    expiresIn = h['expires_in'];
  }

  Future<void> revoke(String authArgs) async {
    // Revokes an AccessToken object.

    if (accessToken == null) {
      throw IllegalArgumentError("Cannot revoke access token; access token is invalid.");
    }

    final props = {
      'token': accessToken,
      'refresh_token': accessToken,
    };

    await PaymentApi().sendAuthRequest(props, 'revoke', PaymentApi.createAuthObject(authArgs));
    accessToken = '';
    refreshToken = '';
    expiresIn = 0;
  }
}

// ################################################################################
//  Exceptions
// ################################################################################

class ApiError {
  // Base class for all API errors.

  //      status: HTTP status code (or None if there is no status).
  //      reference: reference for the error (or None if there is no reference).
  //      error_code: string code for the error (or None if there is no error code).
  //      message: string description of the error (or None if there is no message).
  //      error_data: dictionary containing all the error data (or None if there is no data)

  int? status;
  Map? errorData;
  String? reference;
  String? errorCode;
  String? message;

  ApiError({message, status = 500, errorData}) {
    var err = errorData['error'] as Map;

    reference = errorData['reference'];
    errorCode = err['code'];
    message = err['message'] ?? message;
  }
  String describe() {
    //  Returns a string describing the error.

    return "$runtimeType,$message, (status: $status, error code: $errorCode, reference: $reference)";
  }
}

class BadRequestError implements Exception {
  //  Error raised when the request contains errors.

  //    has_field_errors: boolean indicating whether there are field errors.
  //    field_errors: a list containing all field errors.
  final String message;
  final int responseCode;
  // ignore: prefer_typing_uninitialized_variables
  var responseBody;

  BadRequestError(this.message, this.responseCode, this.responseBody);

  @override
  String toString() {
    return "$message (response code: $responseCode, response body: $responseBody)";
  }
}

class AuthenticationError extends ApiError {
  //  Error raised where there are problems authentication a request.

  AuthenticationError(message, responseCode, responseBody);
}

class IllegalArgumentError extends ArgumentError {
  //  Error raised when passing illegal arguments.

  IllegalArgumentError(String message) : super(message);
}

class ObjectNotFoundError extends ApiError {
  //  Error raised when a requested object cannot be found

  ObjectNotFoundError(message, responseCode, responseBody);
}

class NotAllowedError extends ApiError {
  //  Error raised when a request was not allowed

  NotAllowedError(message, responseCode, responseBody);
}

class SysError extends ApiError {
  //  Error raised when there was a system error processing a request

  SysError(message, responseCode, responseBody);
}

// initiate payment request
class Payment {
  Future<Future<http.Response>> create(Map<String, dynamic> params, dynamic authArgs) async {
    //  Creates an Payment object
    //   @param params: a dict of parameters; valid keys are:
    //       - C{amount}:  Amount of the payment (in the smallest unit of your currency). Example: 100 = $1.00
    //       - C{authorization}:  The ID of the authorization being used to capture the payment.
    //       - C{card => addressCity}:  City of the cardholder. [max length: 50, min length: 2]
    //       - C{card => addressCountry}:  Country code (ISO-3166-1-alpha-2 code) of residence of the cardholder. [max length: 2, min length: 2]
    //       - C{card => addressLine1}:  Address of the cardholder. [max length: 255]
    //       - C{card => addressLine2}:  Address of the cardholder if needed. [max length: 255]
    //       - C{card => addressState}:  State of residence of the cardholder. State abbreviations should be used. [max length: 255]
    //       - C{card => addressZip}:  Postal code of the cardholder. The postal code size is between 5 and 9 in length and only contain numbers or letters. [max length: 32]
    //       - C{card => cvc}:  CVC security code of the card. This is the code on the back of the card. Example: 123
    //       - C{card => expMonth}:  Expiration month of the card. Format is MM. Example: January = 01 [min value: 1, max value: 12]
    //       - C{card => expYear}:  Expiration year of the card. Format is YY. Example: 2013 = 13 [min value: 0, max value: 99]
    //       - C{card => name}:  Name as it appears on the card. [max length: 50, min length: 2]
    //       - C{card => number}:  Card number as it appears on the card. [max length: 19, min length: 13]
    //       - C{currency}:  Currency code (ISO-4217) for the transaction. Must match the currency associated with your account. [default: USD] B{required }
    //       - C{customer}:  ID of customer. If specified, card on file of customer will be used.
    //       - C{description}:  Free form text field to be used as a description of the payment. This field is echoed back with the payment on any find or list operations. [max length: 1024]
    //       - C{invoice}:  ID of invoice for which this payment is being made.
    //       - C{order => commodityCode}:  Standard classification code for products and services. [max length: 5]
    //       - C{order => customer}:  ID of the customer associated with the order.
    //       - C{order => customerEmail}:  Customer email address.
    //       - C{order => customerName}:  Customer name.
    //       - C{order => customerNote}:  Additional notes provided by the customer. [max length: 255]
    //       - C{order => customerReference}:  A merchant reference for the customer.
    //       - C{order => items => amount}:  Cost of the item.
    //       - C{order => items => description}:  Description of the item.
    //       - C{order => items => name}:  Item name.
    //       - C{order => items => product}:  Product information associated with the item.
    //       - C{order => items => quantity}:  Quantity of the item contained in the order [min value: 1, max value: 999999, default: 1] B{required }
    //       - C{order => items => reference}:  A merchant reference for the item. [max length: 255]
    //       - C{order => items => tax}:  Taxes associated with the item.
    //       - C{order => merchantNote}:  Additional notes provided by the merchant. [max length: 255]
    //       - C{order => payment}:  ID of the payment associated with the order.
    //       - C{order => reference}:  A merchant reference for the order. [max length: 255]
    //       - C{order => shippingAddress => city}:  City, town, or municipality. [max length: 255, min length: 2]
    //       - C{order => shippingAddress => country}:  2-character country code. [max length: 2, min length: 2]
    //       - C{order => shippingAddress => line1}:  Street address. [max length: 255]
    //       - C{order => shippingAddress => line2}:  (Opt) Street address continued. [max length: 255]
    //       - C{order => shippingAddress => name}:  Name of the entity being shipped to. [max length: 255]
    //       - C{order => shippingAddress => state}:  State or province. [max length: 255]
    //       - C{order => shippingAddress => zip}:  Postal code. [max length: 32]
    //       - C{order => shippingFromAddress => city}:  City, town, or municipality. [max length: 255, min length: 2]
    //       - C{order => shippingFromAddress => country}:  2-character country code. [max length: 2, min length: 2]
    //       - C{order => shippingFromAddress => line1}:  Street address. [max length: 255]
    //       - C{order => shippingFromAddress => line2}:  (Opt) Street address continued. [max length: 255]
    //       - C{order => shippingFromAddress => name}:  Name of the entity performing the shipping. [max length: 255]
    //       - C{order => shippingFromAddress => state}:  State or province. [max length: 255]
    //       - C{order => shippingFromAddress => zip}:  Postal code. [max length: 32]
    //       - C{order => shippingName}:  Name of the entity being shipped to.
    //       - C{order => source}:  Order source. [default: WEB] B{required }
    //       - C{order => status}:  Status of the order. [default: INCOMPLETE] B{required }
    //       - C{reference}:  Custom reference field to be used with outside systems.
    //       - C{replayId}:  An identifier that can be sent to uniquely identify a payment request to facilitate retries due to I/O related issues. This identifier must be unique for your account (sandbox or live) across all of your payments. If supplied, we will check for a payment on your account that matches this identifier. If found will attempt to return an identical response of the original request. [max length: 50, min length: 1]
    //       - C{statementDescription => name}:  Merchant name. B{required }
    //       - C{statementDescription => phoneNumber}:  Merchant contact phone number.
    //       - C{taxExempt}:  Specify true to indicate that the payment is tax-exempt.
    //       - C{token}:  If specified, card associated with card token will be used. [max length: 255]
    //   @param auth_args: an Authentication object used for the API call.  If no value is passed the gloabl keys simplify.public_key and simplify.private_key are used.
    //       For backwards compatibility the public and private keys may be passed instead of an Authentication object.
    //   @param private_api_key: Private key to use for the API call. If C{None}, the value of C{simplify.private_key} will be used.
    //   @return: a Payment object
    return PaymentApi.create("payment", authArgs, params);
  }

  Future list(Map<String, dynamic> criteria, String authArgs) async {
    // Retrieve Payment objects.
    // @param criteria: a dict of parameters; valid keys are:
    //      - C{filter}  <table class="filter_list"><tr><td>filter.id</td><td>Filter by the payment Id</td></tr><tr><td>filter.replayId</td><td>Filter by the compoundReplayId</td></tr><tr><td>filter.last4</td><td>Filter by the card number (last 4 digits)</td></tr><tr><td>filter.amount</td><td>Filter by the payment amount (in the smallest unit of your currency)</td></tr><tr><td>filter.text</td><td>Filter by the description of the payment</td></tr><tr><td>filter.amountMin & filter.amountMax</td><td>The filter amountMin must be used with amountMax to find payments with payments amounts between the min and max figures</td></tr><tr><td>filter.dateCreatedMin<sup>*</sup></td><td>Filter by the minimum created date you are searching for - Date in UTC millis</td></tr><tr><td>filter.dateCreatedMax<sup>*</sup></td><td>Filter by the maximum created date you are searching for - Date in UTC millis</td></tr><tr><td>filter.deposit</td><td>Filter by the deposit id connected to the payment</td></tr><tr><td>filter.customer</td><td>Filter using the Id of the customer to find the payments for that customer</td></tr><tr><td>filter.status</td><td>Filter by the payment status text</td></tr><tr><td>filter.reference</td><td>Filter by the payment reference text</td></tr><tr><td>filter.authCode</td><td>Filter by the payment authorization code (Not the authorization ID)</td></tr><tr><td>filter.q</td><td>You can use this to filter by the Id, the authCode or the amount of the payment</td></tr></table><br><sup>*</sup>Use dateCreatedMin with dateCreatedMax in the same filter if you want to search between two created dates
    //      - C{max}  Allows up to a max of 50 list items to return. [min value: 0, max value: 50, default: 20]
    //      - C{offset}  Used in paging of the list.  This is the start offset of the page. [min value: 0, default: 0]
    //      - C{sorting}  Allows for ascending or descending sorting of the list. The value maps properties to the sort direction (either C{asc} for ascending or C{desc} for descending).  Sortable properties are:  C{dateCreated} C{createdBy} C{amount} C{id} C{description} C{paymentDate}.
    // @param auth_args: an Authentication object used for the API call.  If no value is passed the gloabl keys simplify.public_key and simplify.private_key are used.
    //     For backwards compatibility the public and private keys may be passed instead of an Authentication object.
    // @return: an object which contains the list of Payment objects in the <code>list</code> property and the total number
    //          of objects available for the given criteria in the <code>total</code> property.
    return PaymentApi.list("payment", authArgs, criteria);
  }

  Future find(String objectId, String authArgs) async {
    //  Retrieve a Payment object from the API
    //       @param object_id: ID of object to retrieve
    //       @param auth_args: an Authentication object used for the API call.  If no value is passed the gloabl keys simplify.public_key and simplify.private_key are used.
    //           For backwards compatibility the public and private keys may be passed instead of an Authentication object.
    //       @return: a Payment object
    return PaymentApi.find("payment", authArgs, objectId);
  }

  Future update(String objectId, String authArgs) {
    //  Updates this object

    //       The properties that can be updated:
    //       @param auth_args: an Authentication object used for the API call.  If no value is passed the gloabl keys simplify.public_key and simplify.private_key are used.
    //           For backwards compatibility the public and private keys may be passed instead of an Authentication object.
    //       @return: a Payment object.
    return PaymentApi.update('payment', authArgs, objectId, toDict());
  }

  toDict() {
    return {};
  }
}

class PaymentApi {
  static Auth createAuthObject(String authArgs) {
    return authArgs.isEmpty ? Auth(publicKey: globalPublicKey) : Auth(publicKey: authArgs[0]);
  }

  static void checkAuth(Auth auth) {
    if (auth == null) {
      throw ArgumentError('Missing authentication object');
    }
    if (auth.publicKey == null) {
      throw ArgumentError('Must have a valid public key to connect to the API');
    }
  }

  static Future<http.Response> create(String objectType, String authArg, Map<String, dynamic> params) async {
    var auth = createAuthObject(authArg);
    var url = buildRequestUrl(objectType);
    var response = await execute(objectType, auth, url, HTTP_METHOD_POST, params);
    return response;
  }

  static Future<dynamic> list(String objectType, String authArgs, Map<String, dynamic> criteria) async {
    final auth = createAuthObject(authArgs);
    var url = buildRequestUrl(objectType);
    final queryString = buildQueryString(criteria);
    if (queryString.isNotEmpty) {
      url = '$url?$queryString';
    }
    final response = await execute(objectType, auth, url, 'GET', criteria);
    return response;
  }

  static Future<dynamic> find(String objectType, String authArgs, String objectId) async {
    final auth = createAuthObject(authArgs);

    if (objectId == null) {
      throw IllegalArgumentError('object_object_id is a required field');
    }
    final url = buildRequestUrl(objectType, objectId);
    final response = await execute(objectType, auth, url, 'GET', objectId as Map<String, dynamic>);
    return response;
  }

  static Future<dynamic> update(
      String objectType, String authArgs, String objectId, Map<String, dynamic> params) async {
    final auth = createAuthObject(authArgs);
    if (objectId == null) {
      throw IllegalArgumentError('object_id is a required field');
    }
    final url = buildRequestUrl(objectType, objectId);
    final response = await execute(objectType, auth, url, 'PUT', params);
    return response;
  }

  static Future<dynamic> delete(String objectType, String authArgs, String objectId) async {
    final auth = createAuthObject(authArgs);
    if (objectId == null) {
      throw IllegalArgumentError('object_id is a required field');
    }
    final url = buildRequestUrl(objectType, objectId);
    final response = await execute(objectType, auth, url, 'DELETE', {});
    return response;
  }

  decode(String authArgs, Map<String, dynamic> params) {
    var auth = PaymentApi.createAuthObject(authArgs);
    PaymentApi.checkAuth(auth);
    Jws j = Jws();

    j.decode(params, auth);
  }

  static Future execute(
      String objectType, Auth auth, String urlSuffix, String method, Map<String, dynamic>? params) async {
    checkAuth(auth);
    var http = Http();
    var baseUrl = cons.apiBaseSandboxUrl;
    if (auth.publicKey!.startsWith('lvpb')) {
      baseUrl = cons.apiBaseLiveUrl;
    }
    var url = '$baseUrl/$urlSuffix';
    var responseBody = await http.request(auth, url, method, params);
    if (responseBody.statusCode != HTTP_SUCCESS) {
      handleHttpError(responseBody.body, responseBody.statusCode);
    }
    dynamic response;
    try {
      response = json.decode(responseBody.body);
    } catch (e) {
      throw SysError(
          'Invalid response format returned.  Have you got the correct URL $url', url, responseBody.statusCode);
    }

    if (response['list'] != null) {
      var obj = [for (var values in response['list']) json.decode(values)];
      obj = response['total'];
      return obj;
    } else {
      return json.decode(responseBody.body);
    }
    // if (response['list'] != null) {
    //   var obj = DomainFactory.factory('domain', params);

    //   obj = [
    //     for (var values in response['list'])
    //       DomainFactory.factory(objectType, values)
    //   ] as Domain;
    //   obj = response['total'];
    //   return obj;
    // } else {
    //   return DomainFactory.factory(objectType, response);
    // }
  }

  static buildRequestUrl(objectType, [objectId = '']) {
    var url = objectType;
    if (objectId.isNotEmpty) {
      url = "$url/$objectId";
    }
    return url;
  }

  Future<Map<String, dynamic>> sendAuthRequest(Map<String, String> props, String context, Auth auth) async {
    checkAuth(auth);

    final http = Http();

    var oauthBaseUrl = cons.oAuthBaseUrl;
    final url = "${oauthBaseUrl!}/$context";

    var response = await http.authRequest(url);
    final responseCode = response.statusCode;
    final responseBody = json.decode(response.body);

    if (responseCode == HTTP_SUCCESS) {
      return responseBody;
    } else if (responseCode == HTTP_REDIRECTED) {
      throw BadRequestError('', responseCode, '');
    } else if (responseCode >= HTTP_BAD_REQUEST) {
      final errorCode = responseBody['error'];
      final errorDesc = responseBody['error_description'];
      if (errorCode == 'invalid_request') {
        throw BadRequestError('', responseCode, getOauthError('Error during OAuth request', errorCode, errorDesc));
      } else if (errorCode == 'access_denied') {
        throw AuthenticationError(
            '', responseCode, getOauthError('Access denied for OAuth request', errorCode, errorDesc));
      } else if (errorCode == 'invalid_client') {
        throw AuthenticationError(
            '', responseCode, getOauthError('Invalid client ID in OAuth request', errorCode, errorDesc));
      } else if (errorCode == 'unauthorized_client') {
        throw AuthenticationError(
            '', responseCode, getOauthError('Unauthorized client in OAuth request', errorCode, errorDesc));
      } else if (errorCode == 'unsupported_grant_type') {
        throw BadRequestError(
            '', responseCode, getOauthError('Unsupported grant type in OAuth request', errorCode, errorDesc));
      } else if (errorCode == 'invalid_scope') {
        throw BadRequestError('', responseCode, getOauthError('Invalid scope in OAuth request', errorCode, errorDesc));
      } else {
        throw BadRequestError('', responseCode, getOauthError('Unknown OAuth error', errorCode, errorDesc));
      }
    } else if (responseCode < 500) {
      throw BadRequestError('Bad request', responseCode, {});
    } else {
      throw SysError('Bad request', responseCode, {});
    }
  }

  String getOauthError(String msg, String errorCode, String errorDesc) {
    return '{"error" : {"code" : "oauth_error", "message" : "$msg, error code $errorCode, description $errorDesc" }}';
  }
}

class Http {
  Http();

  Future<http.Response> request(Auth? auth, var url, String method, Map<String, dynamic>? params) async {
    http.Response response;
    if (method == HTTP_METHOD_POST) {
      response = await http.post(
        url,
        headers: {"Content-Type": "application/json"},
        body: params,
      );
    } else if (method == HTTP_METHOD_PUT) {
      response = await http.put(
        url,
        headers: {"Content-Type": "application/json"},
        body: params,
      );
    } else if (method == HTTP_METHOD_DELETE) {
      response = await http.delete(
        url,
        headers: {"Authorization": "JWS $auth"},
      );
    } else if (method == HTTP_METHOD_GET) {
      response = await http.get(
        url,
        headers: {"Authorization": "JWS $auth"},
      );
    } else {
      throw Exception("HTTP Method $method not recognized");
    }
    return response;
  }

  Future<http.Response> authRequest(var url) async {
    final response = await http.get(
      url,
      headers: {"Authorization": "JWS "},
    );
    return response;
  }
}

class Jws {
  static const int NUM_HEADERS = 7;
  static const String ALGORITHM = 'HS256';
  static const String TYPE = 'JWS';
  static const String HDR_URI = 'api.simplifycommerce.com/uri';
  static const String HDR_TIMESTAMP = 'api.simplifycommerce.com/timestamp';
  static const String HDR_NONCE = 'api.simplifycommerce.com/nonce';
  static const String HDR_TOKEN = 'api.simplifycommerce.com/token';
  static const String HDR_UNAME = 'uname';
  static const String HDR_ALGORITHM = 'alg';
  static const String HDR_TYPE = 'typ';
  static const String HDR_KEY_ID = 'kid';
  static const int TIMESTAMP_MAX_DIFF = 1000 * 60 * 5;

  static String encode(url, auth, params, hasPayload) {
    Map<String, dynamic> jwsHdr = {
      'typ': TYPE,
      'alg': ALGORITHM,
      'kid': auth.publicKey,
      HDR_URI: url,
      HDR_TIMESTAMP: (DateTime.now().millisecondsSinceEpoch / 1000).round(),
      HDR_NONCE: Random().nextInt(10000),
    };

    if (auth.accessToken != null) {
      jwsHdr[HDR_TOKEN] = auth.accessToken;
    }

    String encodedJson = jsonEncode(jwsHdr);
    String header = base64Url.encode(utf8.encode(encodedJson));
    String payload = '';
    if (hasPayload) {
      payload = base64Url.encode(utf8.encode(jsonEncode(params)));
    }

    return '$header.$payload';
  }

  static String authEncode(url, auth, params) {
    Map<String, dynamic> jwsHdr = {
      'typ': TYPE,
      'alg': ALGORITHM,
      'kid': auth.publicKey,
      HDR_URI: url,
      HDR_TIMESTAMP: (DateTime.now().millisecondsSinceEpoch / 1000).round(),
      HDR_NONCE: Random().nextInt(10000),
    };

    String encodedJson = jsonEncode(jwsHdr);
    String header = base64Url.encode(utf8.encode(encodedJson));

    String payload = params.entries.map((e) => '${e.key}=${e.value}').join('&');
    payload = base64Url.encode(utf8.encode(payload));

    return '$header.$payload';
  }

  String sign(String privateApiKey, String msg) {
    var decodedPrivateApiKey = base64Url.decode(privateApiKey);
    var hmac = Hmac(sha256, decodedPrivateApiKey);
    var signature = hmac.convert(utf8.encode(msg)).bytes;
    return base64Url.encode(signature).replaceAll('=', '');
  }

  void verify(String header, String url, String publicApiKey) {
    var hdr = json.decode(header);

    if (hdr.length != NUM_HEADERS) {
      throw Exception('Incorrect number of JWS header parameters - found ${hdr.length} but expected $NUM_HEADERS');
    }

    if (!hdr.containsKey(HDR_ALGORITHM)) {
      throw Exception('Missing algorithm header');
    }

    if (hdr[HDR_ALGORITHM] != ALGORITHM) {
      throw Exception('Incorrect algorithm - found ${hdr[HDR_ALGORITHM]} but required $ALGORITHM');
    }

    if (!hdr.containsKey(HDR_TYPE)) {
      throw Exception('Missing type header');
    }

    if (hdr[HDR_TYPE] != TYPE) {
      throw Exception('Incorrect type - found ${hdr[HDR_TYPE]} but required $TYPE');
    }

    if (!hdr.containsKey(HDR_KEY_ID)) {
      throw Exception('Missing Key ID');
    }

    if (hdr[HDR_KEY_ID] != publicApiKey && publicApiKey.startsWith('lvpb')) {
      throw Exception('Invalid Key ID');
    }

    if (!hdr.containsKey(HDR_NONCE)) {
      throw Exception('Missing nonce');
    }

    if (!hdr.containsKey(HDR_URI)) {
      throw Exception('Missing URI');
    }

    if (hdr[HDR_URI] != url) {
      throw Exception('Incorrect URL - found ${hdr[HDR_URI]} but required $url');
    }

    if (!hdr.containsKey(HDR_TIMESTAMP)) {
      throw Exception('Missing timestamp');
    }

    if (!hdr.containsKey(HDR_UNAME)) {
      throw Exception('Missing username');
    }

    var timeNow = (DateTime.now().millisecondsSinceEpoch / 1000).round();
    var timestamp = hdr[HDR_TIMESTAMP];
    var diff = timeNow - timestamp;

    if (diff > TIMESTAMP_MAX_DIFF) {
      throw Exception('Invalid timestamp, the event has expired');
    }
  }

  void decode(Map<String, dynamic> params, Auth auth) {
    String? publicApiKey = auth.publicKey;
    if (publicApiKey == null) {
      throw ArgumentError('Must have a valid public key to connect to the API');
    }

    if (!params.containsKey('payload')) {
      throw ArgumentError('Event data is missing payload');
    }

    String payload = params['payload'].trim();
    List<String> data = payload.split('.');
    if (data.length != 3) {
      throw ArgumentError('Incorrectly formatted JWS message');
    }

    String header = safeBase64Decode(data[0]).toString();

    String url = '';
    if (params.containsKey('url')) {
      url = params['url'];
    }
    verify(
      publicApiKey,
      url,
      header,
    );

    // ignore: void_checks
    return json.decode(payload);
  }

  Uint8List safeBase64Decode(String url) {
    var length = url.length % 4;
    if (length == 2) {
      return base64Url.decode('$url==');
    }
    if (length == 3) {
      return base64Url.decode('$url=');
    }

    return base64Url.decode(url);
  }

  List<int> encodeJson(String jsonStr) {
    try {
      return utf8.encode(json.encode(jsonStr));
    } catch (e) {
      throw Exception('Invalid format for JSON request');
    }
  }
}

class CardToken {
  var objectId = {};
  Future<dynamic> create(Map<String, dynamic> params, dynamic authArgs) async {
    //       Creates an CardToken object
    //       @param params: a dict of parameters; valid keys are:
    //           - C{authenticatePayer}:  Set as true to create CardToken for EMV 3DS transaction. [default: false]
    //           - C{callback}:  The URL callback for the cardtoken
    //           - C{card => addressCity}:  City of the cardholder. [max length: 50, min length: 2]
    //           - C{card => addressCountry}:  Country code (ISO-3166-1-alpha-2 code) of residence of the cardholder. [max length: 2, min length: 2]
    //           - C{card => addressLine1}:  Address of the cardholder. [max length: 255]
    //           - C{card => addressLine2}:  Address of the cardholder if needed. [max length: 255]
    //           - C{card => addressState}:  State of residence of the cardholder. State abbreviations should be used. [max length: 255]
    //           - C{card => addressZip}:  Postal code of the cardholder. The postal code size is between 5 and 9 in length and only contain numbers or letters. [max length: 32]
    //           - C{card => cvc}:  CVC security code of the card. This is the code on the back of the card. Example: 123
    //           - C{card => expMonth}:  Expiration month of the card. Format is MM. Example: January = 01 [min value: 1, max value: 12]
    //           - C{card => expYear}:  Expiration year of the card. Format is YY. Example: 2013 = 13 [min value: 0, max value: 99]
    //           - C{card => name}:  Name as appears on the card. [max length: 50, min length: 2]
    //           - C{card => number}:  Card number as it appears on the card. [max length: 19, min length: 13]
    //           - C{key}:  Key used to create the card token.
    //           - C{secure3DRequestData => amount}:  Amount of the subsequent transaction in the smallest unit of your currency. Example: 100 = $1.00 B{required }
    //     - C{secure3DRequestData => authOnly}:  Specifies if the subsequent transaction is going to be a Payment or an Authorization (to be Captured later). If false or not specified, it refers to a Payment, otherwise it refers to an Authorization.
    //     - C{secure3DRequestData => currency}:  Currency code (ISO-4217). Must match the currency associated with your account. B{required }
    //     - C{secure3DRequestData => description}:  A description of the transaction. [max length: 256]
    //     - C{secure3DRequestData => id}:  3D Secure data ID.
    //     - C{source}:  Card Token Source [default: API]
    // @param auth_args: an Authentication object used for the API call.  If no value is passed the gloabl keys simplify.public_key and simplify.private_key are used.
    //     For backwards compatibility the public and private keys may be passed instead of an Authentication object.
    // @param private_api_key: Private key to use for the API call. If C{None}, the value of C{simplify.private_key} will be used.
    // @return: a CardToken object
    return await PaymentApi.create("cardToken", authArgs, params);
  }

  Future<dynamic> find(String objectId, String authArgs) async {
    // Retrieve a CardToken object from the API
    // @param object_id: ID of object to retrieve
    // @param auth_args: an Authentication object used for the API call.  If no value is passed the gloabl keys simplify.public_key and simplify.private_key are used.
    //     For backwards compatibility the public and private keys may be passed instead of an Authentication object.
    // @return: a CardToken object

    return await PaymentApi.find("cardToken", authArgs, objectId);
  }

  Future<dynamic> update(String authArgs) async {
    // Updates this object

    // The properties that can be updated:
    //   - C{device => browser} The User-Agent header of the browser the customer used to place the order B{(required)}

    //   - C{device => ipAddress} The IP address of the device used by the payer, in nnn.nnn.nnn.nnn format. B{(required)}

    //   - C{device => language} The language supported for the payer's browser as defined in IETF BCP47.

    //   - C{device => screenHeight} The total height of the payer's browser screen in pixels.

    //   - C{device => screenWidth} The total width of the payer's browser screen in pixels.

    //   - C{device => timeZone} The timezone of the device used by the payer, in Zone ID format. Example: "Europe/Dublin" B{(required)}

    //   - C{key} The public key of the merchant to be used for the token

    // @param auth_args: an Authentication object used for the API call.  If no value is passed the gloabl keys simplify.public_key and simplify.private_key are used.
    //     For backwards compatibility the public and private keys may be passed instead of an Authentication object.
    // @return: a CardToken object.

    return await PaymentApi.update("cardToken", authArgs, '', objectId as Map<String, dynamic>);
  }
}

class Event {
  Event(Map<String, dynamic> data);

  Future<Event> create(Map<String, dynamic> params, String authArgs) async {
    PaymentApi p = PaymentApi();
    var obj = p.decode(authArgs, params);
    if (obj == 'event') {
      throw ApiError();
    }
    return Event(obj['event']);
  }
}

class Refund {
  static Future<dynamic> create(Map<String, dynamic> params, String authArgs) async {
    return await PaymentApi.create("refund", authArgs, params);
  }

  static Future<dynamic> list({Map<String, dynamic>? criteria, String? authArgs}) async {
    return await PaymentApi.list("refund", authArgs!, criteria!);
  }

  static Future<dynamic> find(String objectId, String authArgs) async {
    return await PaymentApi.find("refund", authArgs, objectId);
  }
}

class Invoice {
  final String objectId;

  Invoice(this.objectId);

  static Future<dynamic> create(Map<String, dynamic> params, String authArgs) async {
    // Creates an Invoice object
    //   @param params: a dict of parameters; valid keys are:
    //       - C{billingAddress => city}:  Billing address city of the location where the goods or services were supplied. [max length: 255, min length: 2]
    //       - C{billingAddress => country}:  Billing address country of the location where the goods or services were supplied. [max length: 2, min length: 2]
    //       - C{billingAddress => line1}:  Billing address line 1 of the location where the goods or services were supplied. [max length: 255]
    //       - C{billingAddress => line2}:  Billing address line 2 of the location where the goods or services were supplied. [max length: 255]
    //       - C{billingAddress => name}:  Billing address name of the location where the goods or services were supplied. Will use the customer name if not provided. [max length: 255]
    //       - C{billingAddress => state}:  Billing address state of the location where the goods or services were supplied. [max length: 255]
    //       - C{billingAddress => zip}:  Billing address zip of the location where the goods or services were supplied. [max length: 32]
    //       - C{businessAddress => city}:  Address city of the business that is sending the invoice. [max length: 255, min length: 2]
    //       - C{businessAddress => country}:  Address country of the business that is sending the invoice. [max length: 2, min length: 2]
    //       - C{businessAddress => line1}:  Address line 1 of the business that is sending the invoice. [max length: 255]
    //       - C{businessAddress => line2}:  Address line 2 of the business that is sending the invoice. [max length: 255]
    //       - C{businessAddress => name}:  The name of the business that is sending the invoice. [max length: 255]
    //       - C{businessAddress => state}:  Address state of the business that is sending the invoice. [max length: 255]
    //       - C{businessAddress => zip}:  Address zip of the business that is sending the invoice. [max length: 32]
    //       - C{currency}:  Currency code (ISO-4217). Must match the currency associated with your account. [max length: 3, min length: 3]
    //       - C{customer}:  The customer ID of the customer we are invoicing.  This is optional if invoiceToCopy or a name and email are provided
    //       - C{customerTaxNo}:  The tax number or VAT id of the person to whom the goods or services were supplied. [max length: 255]
    //       - C{discountRate}:  The discount percent as a decimal e.g. 12.5.  This is used to calculate the discount amount which is subtracted from the total amount due before any tax is applied. [max length: 6]
    //       - C{dueDate}:  The date invoice payment is due.  If a late fee is provided this will be added to the invoice total is the due date has past.
    //       - C{email}:  The email of the customer we are invoicing.  This is optional if customer or invoiceToCopy is provided.  A new customer will be created using the the name and email.
    //       - C{invoiceId}:  User defined invoice id. If not provided the system will generate a numeric id. [max length: 255]
    //       - C{invoiceLanguage}:  The language in which invoice will be displayed. [max length: 5, min length: 5]
    //       - C{invoiceToCopy}:  The id of an existing invoice to be copied.  This is optional if customer or a name and email are provided
    //       - C{items => amount}:  Amount of the invoice item (the smallest unit of your currency). Example: 100 = $1.00 B{required }
    //       - C{items => description}:  The description of the invoice item. [max length: 1024]
    //       - C{items => invoice}:  The ID of the invoice this item belongs to.
    //       - C{items => product}:  The product this invoice item refers to.
    //       - C{items => quantity}:  Quantity of the item.  This total amount of the invoice item is the amount * quantity. [min value: 1, max value: 999999, default: 1]
    //       - C{items => reference}:  User defined reference field. [max length: 255]
    //       - C{items => tax}:  The tax ID of the tax charge in the invoice item.
    //       - C{lateFee}:  The late fee amount that will be added to the invoice total is the due date is past due.  Value provided must be in the smallest unit of your currency. Example: 100 = $1.00
    //       - C{memo}:  A memo that is displayed to the customer on the invoice payment screen. [max length: 4000]
    //       - C{name}:  The name of the customer we are invoicing.  This is optional if customer or invoiceToCopy is provided.  A new customer will be created using the the name and email. [max length: 50, min length: 2]
    //       - C{note}:  This field can be used to store a note that is not displayed to the customer. [max length: 4000]
    //       - C{reference}:  User defined reference field. [max length: 255]
    //       - C{shippingAddress => city}:  Address city of the location where the goods or services were supplied. [max length: 255, min length: 2]
    //       - C{shippingAddress => country}:  Address country of the location where the goods or services were supplied. [max length: 2, min length: 2]
    //       - C{shippingAddress => line1}:  Address line 1 of the location where the goods or services were supplied. [max length: 255]
    //       - C{shippingAddress => line2}:  Address line 2 of the location where the goods or services were supplied. [max length: 255]
    //       - C{shippingAddress => name}:  Address name of the location where the goods or services were supplied. [max length: 255]
    //       - C{shippingAddress => state}:  Address state of the location where the goods or services were supplied. [max length: 255]
    //       - C{shippingAddress => zip}:  Address zip of the location where the goods or services were supplied. [max length: 32]
    //       - C{suppliedDate}:  The date on which the goods or services were supplied.
    //       - C{taxNo}:  The tax number or VAT id of the person who supplied the goods or services. [max length: 255]
    //       - C{type}:  The type of invoice.  One of WEB or MOBILE. [valid values: WEB, MOBILE, default: WEB]
    //   @param auth_args: an Authentication object used for the API call.  If no value is passed the gloabl keys simplify.public_key and simplify.private_key are used.
    //       For backwards compatibility the public and private keys may be passed instead of an Authentication object.
    //   @param private_api_key: Private key to use for the API call. If C{None}, the value of C{simplify.private_key} will be used.
    //   @return: a Invoice object
    return await PaymentApi.create("invoice", authArgs, params);
  }

  Future<dynamic> delete(String authArgs) async {
    // Delete this object
    //         @param auth_args: an Authentication object used for the API call.  If no value is passed the gloabl keys simplify.public_key and simplify.private_key are used.
    //             For backwards compatibility the public and private keys may be passed instead of an Authentication object.
    return await PaymentApi.delete("invoice", authArgs, objectId);
  }

  static Future<dynamic> list({Map<String, dynamic>? criteria, String? authArgs}) async {
    // Retrieve Invoice objects.
    //   @param criteria: a dict of parameters; valid keys are:
    //        - C{filter}  <table class="filter_list"><tr><td>filter.id</td><td>Filter by the invoice Id</td></tr><tr><td>filter.amount</td><td>Filter by the invoice amount (in the smallest unit of your currency)</td></tr><tr><td>filter.text</td><td>Filter by the name of the invoice</td></tr><tr><td>filter.dateCreatedMin<sup>*</sup></td><td>Filter by the minimum created date you are searching for - Date in UTC millis</td></tr><tr><td>filter.dateCreatedMax<sup>*</sup></td><td>Filter by the maximum created date you are searching for - Date in UTC millis</td></tr><tr><td>filter.datePaidMin<sup>*</sup></td><td>Filter by the minimum invoice paid date you are searching for - Date in UTC millis</td></tr><tr><td>filter.datePaidMax<sup>*</sup></td><td>Filter by the maximum invoice paid date you are searching for - Date in UTC millis</td></tr><tr><td>filter.status</td><td>Filter by the status of the invoice</td></tr><tr><td>filter.statuses</td><td>Filter by multiple statuses of different invoices</td></tr><tr><td>filter.customer</td><td>Filter using the Id of the customer linked to the invoice</td></tr><tr><td>filter.type</td><td>Filter by the invoice type</td></tr><tr><td>filter.types</td><td>Filter by multiple invoice types</td></tr><tr><td>filter.invoiceId</td><td>Filter by the user defined invoice id</td></tr><tr><td>filter.reference</td><td>Filter by the invoice reference text</td></tr></table><br><sup>*</sup>The filters datePaidMin and datePaidMax can be used in the same filter if you want to search between the two dates. The same is for dateCreatedMin/dateCreatedMax.
    //        - C{max}  Allows up to a max of 50 list items to return. [min value: 0, max value: 50, default: 20]
    //        - C{offset}  Used in paging of the list.  This is the start offset of the page. [min value: 0, default: 0]
    //        - C{sorting}  Allows for ascending or descending sorting of the list. The value maps properties to the sort direction (either C{asc} for ascending or C{desc} for descending).  Sortable properties are:  C{id} C{invoiceDate} C{dueDate} C{datePaid} C{customer} C{status} C{dateCreated}.
    //   @param auth_args: an Authentication object used for the API call.  If no value is passed the gloabl keys simplify.public_key and simplify.private_key are used.
    //       For backwards compatibility the public and private keys may be passed instead of an Authentication object.
    //   @return: an object which contains the list of Invoice objects in the <code>list</code> property and the total number
    //            of objects available for the given criteria in the <code>total</code> property.
    return await PaymentApi.list("invoice", authArgs!, criteria!);
  }

  static Future<dynamic> find(String objectId, String authArgs) async {
    // Retrieve a Invoice object from the API
    //       @param object_id: ID of object to retrieve
    //       @param auth_args: an Authentication object used for the API call.  If no value is passed the gloabl keys simplify.public_key and simplify.private_key are used.
    //           For backwards compatibility the public and private keys may be passed instead of an Authentication object.
    //       @return: a Invoice object
    return await PaymentApi.find("invoice", authArgs, objectId);
  }

  Future<dynamic> update(String authArgs) async {
    return await PaymentApi.update("invoice", authArgs, objectId, toDict());
  }

  toDict() {
    return {};
  }
}

class InvoiceItem {
  final String objectId;

  InvoiceItem(this.objectId);

  static Future<dynamic> create(Map<String, dynamic> params, String authArgs) async {
    // Creates an InvoiceItem object
    //   @param params: a dict of parameters; valid keys are:
    //       - C{amount}:  Amount of the invoice item in the smallest unit of your currency. Example: 100 = $1.00 B{required }
    //       - C{description}:  Individual items of an invoice [max length: 1024]
    //       - C{invoice}:  The ID of the invoice this item belongs to.
    //       - C{product}:  Product ID this item relates to.
    //       - C{quantity}:  Quantity of the item.  This total amount of the invoice item is the amount * quantity. [min value: 1, max value: 999999, default: 1]
    //       - C{reference}:  User defined reference field. [max length: 255]
    //       - C{tax}:  The tax ID of the tax charge in the invoice item.
    //   @param auth_args: an Authentication object used for the API call.  If no value is passed the gloabl keys simplify.public_key and simplify.private_key are used.
    //       For backwards compatibility the public and private keys may be passed instead of an Authentication object.
    //   @param private_api_key: Private key to use for the API call. If C{None}, the value of C{simplify.private_key} will be used.
    //   @return: a InvoiceItem object
    return await PaymentApi.create("invoiceItem", authArgs, params);
  }

  Future<dynamic> delete(String authArgs) async {
    // Delete this object
    //         @param auth_args: an Authentication object used for the API call.  If no value is passed the gloabl keys simplify.public_key and simplify.private_key are used.
    //             For backwards compatibility the public and private keys may be passed instead of an Authentication object.
    return await PaymentApi.delete("invoiceItem", authArgs, objectId);
  }

  static Future<dynamic> find(String objectId, String authArgs) async {
    // Retrieve a InvoiceItem object from the API
    //       @param object_id: ID of object to retrieve
    //       @param auth_args: an Authentication object used for the API call.  If no value is passed the gloabl keys simplify.public_key and simplify.private_key are used.
    //           For backwards compatibility the public and private keys may be passed instead of an Authentication object.
    //       @return: a InvoiceItem object
    return await PaymentApi.find("invoiceItem", authArgs, objectId);
  }

  Future<dynamic> update(String authArgs) async {
    //  Updates this object

    //       The properties that can be updated:
    //         - C{amount} Amount of the invoice item in the smallest unit of your currency. Example: 100 = $1.00 [min value: 1]

    //         - C{description} Individual items of an invoice

    //         - C{quantity} Quantity of the item.  This total amount of the invoice item is the amount * quantity. [min value: 1, max value: 999999]

    //         - C{reference} User defined reference field.

    //         - C{tax} The tax ID of the tax charge in the invoice item.

    //       @param auth_args: an Authentication object used for the API call.  If no value is passed the gloabl keys simplify.public_key and simplify.private_key are used.
    //           For backwards compatibility the public and private keys may be passed instead of an Authentication object.
    //       @return: a InvoiceItem object.
    return await PaymentApi.update("invoiceItem", authArgs, objectId, toDict());
  }

  Map<String, dynamic> toDict() {
    return {};
  }
}

class Customer {
  final String objectId;

  Customer(this.objectId);

  static Future<dynamic> create(Map<String, dynamic> params, String authArgs) async {
    return await PaymentApi.create("customer", authArgs, params);
  }

  Future<dynamic> delete(String authArgs) async {
    return await PaymentApi.delete("customer", authArgs, objectId);
  }

  static Future<dynamic> list(Map<String, dynamic> criteria, String authArgs) async {
    return await PaymentApi.list("customer", authArgs, criteria);
  }

  static Future<dynamic> find(String objectId, String authArgs) async {
    return await PaymentApi.find("customer", authArgs, objectId);
  }

  Future<dynamic> update(String authArgs) async {
    return await PaymentApi.update("customer", authArgs, objectId, toDict());
  }

  Map<String, dynamic> toDict() {
    return {};
  }
}

class Coupon {
  final String objectId;

  Coupon(this.objectId);

  static Future<dynamic> create(Map<String, dynamic> params, String authArgs) async {
    return await PaymentApi.create("coupon", authArgs, params);
  }

  Future<dynamic> delete(String authArgs) async {
    return await PaymentApi.delete("coupon", authArgs, objectId);
  }

  static Future<dynamic> list(Map<String, dynamic> criteria, String authArgs) async {
    return await PaymentApi.list("coupon", authArgs, criteria);
  }

  static Future<dynamic> find(String objectId, String authArgs) async {
    return await PaymentApi.find("coupon", authArgs, objectId);
  }

  Future<dynamic> update(String authArgs) async {
    return await PaymentApi.update("coupon", authArgs, objectId, toDict());
  }

  Map<String, dynamic> toDict() {
    return {};
  }
}
