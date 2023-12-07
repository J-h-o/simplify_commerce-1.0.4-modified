import 'package:reflectable/reflectable.dart';
import 'dart:convert';

//
//

const reflectable = Reflectable;

@reflectable
class Domain extends Reflectable {
  Map<String, dynamic> data = {};
  dynamic objectId;

  Domain({Map<String, dynamic>? values}) : data = values ?? {};

  dynamic operator [](String key) {
    if (data.containsKey(key)) {
      return data[key];
    } else {
      throw Exception('Key not found in data map: $key');
    }
  }

  void operator []=(String key, dynamic value) {
    data[key] = value;
  }

  Map<String, dynamic> toJson() {
    Map<String, dynamic> jsonData = {};
    data.forEach((key, value) {
      if (value is Domain) {
        jsonData[key] = value.toJson();
      } else {
        jsonData[key] = value;
      }
    });
    return jsonData;
  }

  String className() {
    return runtimeType.toString().toLowerCase();
  }

  @override
  String toString() {
    return jsonEncode(toJson());
  }
}

Domain d = Domain();

class PaymentObjectEncoder {
  String convert(Object? object) {
    if (object is Domain) {
      return object.toJson().toString();
    } else {
      return JsonEncoder().convert(object);
    }
  }
}

dynamic buildPaymentObject(String typ, dynamic value) {
  if (value is Map || value is Domain) {
    return DomainFactory.factory(typ, value);
  } else {
    throw Exception('Invalid value for payment object: $value');
  }
}

class DomainFactory {
  static Map<String, Type> cache = {};

  static factory(String moduleName, [Map<dynamic, dynamic>? values]) {
    var className = '${moduleName[0].toUpperCase()}${moduleName[1]}';
    try {
      final type = cache[className] ??= d.reflectType(className as Type) as Type;
      final ClassMirror classMirror = d.reflectType(type).reflectedType as ClassMirror;
      return values != null ? classMirror.newInstance('', []) : classMirror.newInstance('', []);
    } catch (e) {
      return Domain(values: values as Map<String, dynamic>);
    }
  }
}
