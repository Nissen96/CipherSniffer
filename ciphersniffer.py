#!/usr/bin/env python3

import argparse
import logging
import struct


# Progress bar wrapper for iterators, initialized to do nothing
tqdm = lambda x, **_: x


# Setup custom logging format
class CustomFormatter(logging.Formatter):
    FORMATS = {
        logging.DEBUG: "\x1b[32;20m%(message)s\x1b[0m",
        logging.INFO: "\x1b[36;20m%(message)s\x1b[0m",
        logging.WARNING: "\x1b[33;20m%(message)s\x1b[0m",
        logging.ERROR: "\x1b[31;20m%(message)s\x1b[0m",
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ch.setFormatter(CustomFormatter())
logger.addHandler(ch)

# Constant values used by specific cryptographic methods
CRYPTO_CONSTS = {
    "AES": {
        "Rcon": [
            0x01020408, 0x10204080, 0x1b366cd8
        ],
        "S-box": [
            0x637C777B, 0xF26B6FC5, 0x3001672B, 0xFED7AB76, 0xCA82C97D, 0xFA5947F0, 0xADD4A2AF, 0x9CA472C0,
            0xB7FD9326, 0x363FF7CC, 0x34A5E5F1, 0x71D83115, 0x04C723C3, 0x1896059A, 0x071280E2, 0xEB27B275,
            0x09832C1A, 0x1B6E5AA0, 0x523BD6B3, 0x29E32F84, 0x53D100ED, 0x20FCB15B, 0x6ACBBE39, 0x4A4C58CF,
            0xD0EFAAFB, 0x434D3385, 0x45F9027F, 0x503C9FA8, 0x51A3408F, 0x929D38F5, 0xBCB6DA21, 0x10FFF3D2,
            0xCD0C13EC, 0x5F974417, 0xC4A77E3D, 0x645D1973, 0x60814FDC, 0x222A9088, 0x46EEB814, 0xDE5E0BDB,
            0xE0323A0A, 0x4906245C, 0xC2D3AC62, 0x9195E479, 0xE7C8376D, 0x8DD54EA9, 0x6C56F4EA, 0x657AAE08,
            0xBA78252E, 0x1CA6B4C6, 0xE8DD741F, 0x4BBD8B8A, 0x703EB566, 0x4803F60E, 0x613557B9, 0x86C11D9E,
            0xE1F89811, 0x69D98E94, 0x9B1E87E9, 0xCE5528DF, 0x8CA1890D, 0xBFE64268, 0x41992D0F, 0xB054BB16,
        ],
        "Reverse S-box": [
            0x52096ad5, 0x3036a538, 0xbf40a39e, 0x81f3d7fb, 0x7ce33982, 0x9b2fff87, 0x348e4344, 0xc4dee9cb,
            0x547b9432, 0xa6c2233d, 0xee4c950b, 0x42fac34e, 0x082ea166, 0x28d924b2, 0x765ba249, 0x6d8bd125,
            0x72f8f664, 0x86689816, 0xd4a45ccc, 0x5d65b692, 0x6c704850, 0xfdedb9da, 0x5e154657, 0xa78d9d84,
            0x90d8ab00, 0x8cbcd30a, 0xf7e45805, 0xb8b34506, 0xd02c1e8f, 0xca3f0f02, 0xc1afbd03, 0x01138a6b,
            0x3a911141, 0x4f67dcea, 0x97f2cfce, 0xf0b4e673, 0x96ac7422, 0xe7ad3585, 0xe2f937e8, 0x1c75df6e,
            0x47f11a71, 0x1d29c589, 0x6fb7620e, 0xaa18be1b, 0xfc563e4b, 0xc6d27920, 0x9adbc0fe, 0x78cd5af4,
            0x1fdda833, 0x8807c731, 0xb1121059, 0x2780ec5f, 0x60517fa9, 0x19b54a0d, 0x2de57a9f, 0x93c99cef,
            0xa0e03b4d, 0xae2af5b0, 0xc8ebbb3c, 0x83539961, 0x172b047e, 0xba77d626, 0xe1691463, 0x55210c7d,
        ],
    },
    "Salsa20 / ChaCha20": {
        "Init": [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574],
    },
    "Base64": {
        "Char map": [
            0x41424344, 0x45464748, 0x494A4B4C, 0x4D4E4F50,
            0x51525354, 0x55565758, 0x595A6162, 0x63646566,
            0x6768696A, 0x6B6C6D6E, 0x6F707172, 0x73747576,
            0x7778797A, 0x30313233, 0x34353637, 0x38392B2F,
        ],
        "Decode map (00)": [
            0x0000003E, 0x0000003F, 0x34353637, 0x38393A3B,
            0x3C3D0000, 0x00000102, 0x03040506, 0x0708090A,
            0x0B0C0D0E, 0x0F101112, 0x13141516, 0x17181900,
            0x001A1B1C, 0x1D1E1F20, 0x21222324, 0x25262728,
            0x292A2B2C, 0x2D2E2F30, 0x31323300,
        ],
        "Decode map (FF)": [
            0xFFFFFF3E, 0xFFFFFF3F, 0x34353637, 0x38393A3B,
            0x3C3DFFFF, 0xFF000102, 0x03040506, 0x0708090A,
            0x0B0C0D0E, 0x0F101112, 0x13141516, 0x171819FF,
            0xFF1A1B1C, 0x1D1E1F20, 0x21222324, 0x25262728,
            0x292A2B2C, 0x2D2E2F30, 0x313233FF,
        ],
    },
    "CRC-32": {
        "Polynomial 1": [0x04C11DB7],
        "Polynomial 2": [0xdebb20e3],
        "Generator": [0xEDB88320],
        "Poly Table": [
            0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
            0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
            0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
            0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
            0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
            0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
            0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
            0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
            0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
            0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
            0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
            0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
            0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
            0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
            0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
            0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
            0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
            0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
            0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
            0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
            0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
            0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
            0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
            0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
            0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
            0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
            0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
            0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
            0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
            0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
            0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
            0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D,
        ],
    },
    "MD4 / MD5 / SHA-1": {
        "Init": [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476],
        "[MD4 / SHA-1] Consts": [0x5a827999, 0x6ed9eba1],
        "[SHA-1] Consts": [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6],
        "[MD5] Consts": [
            0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE, 0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
            0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE, 0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
            0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA, 0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
            0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED, 0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
            0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C, 0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
            0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05, 0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
            0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039, 0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
            0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1, 0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
        ],
    },
    "SHA-224 / SHA-256": {
        "Round Consts": [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
        ],
        "[SHA-224] Init": [
            0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
            0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
        ],
        "[SHA-256] Init": [
            0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
            0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
        ]
    },
    "SHA-384 / SHA-512": {
        "Round Consts": [
            0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd, 0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc,
            0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019, 0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118,
            0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe, 0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
            0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1, 0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694,
            0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3, 0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
            0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483, 0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
            0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210, 0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4,
            0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725, 0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70,
            0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926, 0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
            0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8, 0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
            0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001, 0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30,
            0xd192e819, 0xd6ef5218, 0xd6990624, 0x5565a910, 0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
            0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53, 0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8,
            0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb, 0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3,
            0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60, 0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
            0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9, 0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b,
            0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207, 0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178,
            0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6, 0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
            0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493, 0x3c9ebe0a, 0x15c9bebc, 0x431d67c4, 0x9c100d4c,
            0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a, 0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817,
        ],
        "[SHA-384] Init": [
            0xcbbb9d5d, 0xc1059ed8, 0x629a292a, 0x367cd507,
            0x9159015a, 0x3070dd17, 0x152fecd8, 0xf70e5939,
            0x67332667, 0xffc00b31, 0x8eb44a87, 0x68581511,
            0xdb0c2e0d, 0x64f98fa7, 0x47b5481d, 0xbefa4fa4,
        ],
        "[SHA-512] Init": [
            0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b,
            0x3c6ef372, 0xfe94f82b, 0xa54ff53a, 0x5f1d36f1,
            0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f,
            0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179,
        ],
    },
    "TEA / XTEA / XXTEA": {
        "Delta": [0x9E3779B9],
        "[TEA] Sum": [0xC6EF3720],
    },
    "ZipCrypto": {
        "Keys": [0x12345678, 0x23456789, 0x34567890],
        "LCG a": [0x08088405],
    },
    "FNV": {
        "Prime": [0x01000193],
        "Offset": [0x811c9dc5],
    },
    "Whirlpool": {
        "S-box": [
            0xE8C62318, 0x4F01B887, 0xF5D2A636, 0x52916F79, 0x8E9BBC60, 0x357B0CA3, 0xC2D7E01D, 0x57FE4B2E,
            0xE5377715, 0xDA4AF09F, 0x0A29C958, 0x856BA0B1, 0xF4105DBD, 0x67053ECB, 0x8B4127E4, 0xD8957DA7,
            0x667CEEFB, 0x9E4717DD, 0x07BF2DCA, 0x33835AAD, 0x71AA0263, 0xD94919C8, 0x885BE3F2, 0xB032269A,
            0x80D50FE9, 0x4834CDBE, 0x5F907AFF, 0xAE1A6820, 0x229354B4, 0x1273F164, 0xECC30840, 0x3D8DA1DB,
            0x2BCF0097, 0x1BD68276, 0x506AAFB5, 0xEF30F345, 0xEAA2553F, 0xC02FBA65, 0x4DFD1CDE, 0x8A067592,
            0x1F0EE6B2, 0x96A8D462, 0x5925C5F9, 0x4C397284, 0x8C38785E, 0x61E2A5D1, 0x1E9C21B3, 0x04FCC743,
            0x0D6D9951, 0x247EDFFA, 0x11CEAB3B, 0xEBB74E8F, 0xF794813C, 0xD32C13B9, 0x03C46EE7, 0xA97F4456,
            0x53C1BB2A, 0x6C9D0BDC, 0x46F67431, 0xE11489AC, 0x09693A16, 0xEDD0B670, 0xA49842CC, 0x86F85C28,
        ],
    },
    "LCG params": {
        "C/C++": [0x41c64e6d],
        "Delphi/Pascal": [0x08088405],
        "VBA": [0x00fd43fd],
    }
}


def find_constants(data: bytes, indicator: str, sequence: list[int], endian: str) -> int:
    format = "<I" if endian == "LE" else ">I"

    # Search for constants sequentially in data
    # Does not need to be consecutive, just in order
    found = []
    const = sequence[0]
    for i in tqdm(range(len(data) - 4), leave=False, desc=f"  {indicator} <{endian}>"):
        val = struct.unpack(f"{format}", data[i:i + 4])[0]
        if val != const:
            continue

        found.append(i)
        if len(found) == len(sequence):
            break

        const = sequence[len(found)]

    # Consecutive here means each constant is at most 256 bytes away from the previous
    # This prevents most false negatives due to padding etc. while distance is still low
    consecutive = all(found[i + 1] - found[i] <= 256 for i in range(len(found) - 1))

    return len(found), consecutive


def find_longest_match(data: bytes, indicator: str, sequence: list[int]) -> int:
    # Find matches in little- and big-endian
    found_le, consecutive_le = find_constants(data, indicator, sequence, endian="LE")
    found_be, consecutive_be = find_constants(data, indicator, sequence, endian="BE")

    # Prioritize longest match highest, then consecutiveness
    if found_be > found_le or (found_be == found_le and consecutive_be):
        return found_be, "BE", consecutive_be

    if found_le > found_be or (found_be == found_le and consecutive_le):
        return found_le, "LE", consecutive_le

    # Arbitrary big-endian default
    return found_be, "BE", consecutive_be


def detect_algorithms(data, filters):
    # For each chosen algorithm, detect its presence by finding indicator sequences
    for algo, indicators in CRYPTO_CONSTS.items():
        if all(filter.strip() not in algo.lower() for filter in filters):
            continue

        logging.info(f"[{algo}]")
        for indicator, sequence in indicators.items():
            found, endian, consecutive = find_longest_match(data, indicator, sequence)

            n = len(sequence)
            format = f"  {indicator} <{endian}>: {found}/{n}"
            if not consecutive:
                    format += " (fragmented)"

            if found == n and consecutive:
                logging.debug(format)
            elif found > 0:
                logging.warning(format)
            else:
                logging.error(f"  {indicator}: {found}/{n}")
        print()


def list_supported_algorithms():
    logging.info("Supported algorithms:")
    for entry in CRYPTO_CONSTS:
        for algo in entry.split("/"):
            logging.debug(f"  {algo.strip()}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detect cryptographic algorithms in binary data")
    parser.add_argument("file", nargs="?", type=argparse.FileType("rb"), help="Binary data file")
    parser.add_argument("-p", "--progress", action="store_true", help="Show progress bars")
    parser.add_argument("-f", "--filter", default="", help="Algorithm(s) to detect, e.g. 'cha,md,zip'")
    parser.add_argument("-l", "--list", action="store_true", help="List supported algorithms")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.list:
        list_supported_algorithms()
        return

    if args.file is None:
        logging.error("[!] Input file is required!")
        return

    # Update trange function to use tqdm for automatic progress bar
    if args.progress:
        global tqdm
        try:
            from tqdm import tqdm
        except ImportError:
            logging.error("[!] For progress bar support, please install 'tqdm' with pip\n")

    filters = args.filter.lower().split(",")
    with args.file as f:
        data = f.read()

    detect_algorithms(data, filters)


if __name__ == "__main__":
    main()
