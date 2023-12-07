Simplify Dart Package



To run a payment though Simplify Commerce use the following
script substituting your public and private API keys:


globalPublicKey = "YOUR_PUBLIC_API_KEY"
globalPrivateKey = "YOUR_PRIVATE_API_KEY"


import simplify
Simplify payment = Simplify();

# call instance of the object
payment = simplify.create({
       	"card" : {
            "number": "5555555555554444",
            "expMonth": 11,
            "expYear": 15,
            "cvc": "123"
        },
        "amount" : "1000",
        "description" : "prod description",
        "currency" : "USD"
})
print payment