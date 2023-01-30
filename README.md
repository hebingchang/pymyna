# PyMyna
A Python interface to interact with [My Number Card (マイナンバーカード)](https://www.kojinbango-card.go.jp/).

🚧 This package is still under heavy development and cannot work properly. DO NOT USE IT IN PRODUCTION!

## Usage
```
usage: myna [-h] {jpki,text,visual} ...

positional arguments:
  {jpki,text,visual}
    jpki              JPKI AP related commands.
    text              Text AP related commands.
    visual            Visual AP related commands.

options:
  -h, --help          show this help message and exit
```

## Supported Devices
- [Sony PaSoRi RC-S300/S](https://www.sony.co.jp/Products/felica/business/products/reader/RC-S300.html)

## Unit Test
`AUTH_PIN=${your_auth_pin} SIGN_PIN=${your_sign_pin} python3 myna/myna_test.py`

## Troubleshooting
- **In case an invalid PIN error is thrown:**\
  If you believe you have the right PIN, it should be a bug of this package. To avoid the card being locked due to many failed PIN attempts, please use the [official application](https://www.jpki.go.jp/download/) to verify your PIN. This will reset the failed attempts.