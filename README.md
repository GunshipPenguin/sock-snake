# Sock Snake

A SOCKS4a proxy implementation in Python 3.

The SOCKS4 and SOCKS4a specifications can be found in `socks4.protocol` and
`socks4a.protocol` respectively.

## Usage

```
$ python3 socksnake.py --help
usage: socksnake.py [-h] [--port PORT]

SOCKS4a Proxy Implementation

optional arguments:
  -h, --help   show this help message and exit
  --port PORT  port to listen for incoming SOCKS requests on (default: 1080)

Homepage: https://github.com/GunshipPenguin/sock-snake
```

## Tests

`python3 test.py`

## License

[MIT](https://github.com/GunshipPenguin/sock-snake/blob/master/LICENSE) © Rhys Rustad-Elliott
