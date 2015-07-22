// not tried -- would require to extract sha256 algorithm from test script
// https://github.com/Kukunin/asm.js-benchmark

// https://github.com/crypto-browserify/sha.js
import createHash from 'sha.js';

// http://pajhome.org.uk/crypt/md5/index.html
// 12K unminified
import pajhome from 'hash-implementations/pajhome_sha256';

// http://anmar.eu.org/projects/jssha2/
// 3.6K unminified
import jssha2 from 'hash-implementations/jsSha2/sha256';

// https://github.com/digitalbazaar/forge
import forge from 'hash-implementations/forge.min';

// https://github.com/chrisveness/crypto
// 7.1K unminified
import chrisveness from 'hash-implementations/chrisveness_sha256';

// https://github.com/dchest/blake2s-js
// 12K
import BLAKE2s from 'hash-implementations/blake2s.min';

// https://github.com/brianloveswords/buffer-crc32
import buffer_crc32 from 'buffer-crc32';

const IMPLEMENTATIONS = [ 
    (function(){
        function wide_char_exists(str){
            for( var i = 0; i < str.length; i++ ){
                if ( str.charCodeAt(i) >>> 8 ) return true;
            }
            return false;
        }

        return {
            name: 'forge [conditional UTF8]',
            hash_function: 'sha256',
            source: 'https://github.com/brillout/forge-sha256',
            compute: function(text){
                var md = forge.md.sha256.create();
                md.update(
                    text,
                    wide_char_exists(text)?'utf8':undefined);
                return md.digest().toHex();
            }
        };
    })(),
    {
        name: 'forge',
        hash_function: 'sha256',
        source: 'https://github.com/digitalbazaar/forge',
        size: '284K',
        compute: function(text){
            var md = forge.md.sha256.create();
            md.update(text);
            return md.digest().toHex();
        }
    },
    {
        name: 'forge [UTF8]',
        hash_function: 'sha256',
        source: 'https://github.com/digitalbazaar/forge',
        compute: function(text){
            var md = forge.md.sha256.create();
            md.update(text, 'utf8');
            return md.digest().toHex();
        }
    },

    {
        name: 'jssha2',
        source: 'http://anmar.eu.org/projects/jssha2/',
        size: '3.6K unminified',
        hash_function: 'sha256',
        compute: function(text){
            return jssha2.hex_sha256(text);
        }
    },

    {
        name: 'asmCrypto',
        source: 'https://github.com/vibornoff/asmcrypto.js',
        hash_function: 'sha256',
        compute: function(text){
            return asmCrypto.SHA256.hex(text);
        }
    },

    {
        name: 'crypto-browserify/sha.js',
        source: 'https://github.com/crypto-browserify/sha.js',
        hash_function: 'sha256',
        compute: function(text) {
            var sha = createHash('sha256');
            return sha.update(text,'utf8').digest('hex');
        }
    },

    {
        name: 'CryptoJS',
        source: 'https://code.google.com/p/crypto-js/',
        size: '16K',
        hash_function: 'sha256',
        compute: function(text){
            return CryptoJS.SHA256(text).toString();
        }
    },

    // 
    /* can't make it work
    (function(){
        var sha = Module.cwrap('sha_simple', 'string', ['string']);
        return {
            name: 'pbkdf-sha256-asm',
            source: 'https://github.com/sitegui/pbkdf-sha256-asm',
            hash_function: 'sha256',
            compute: function(text){
                return sha(text);
            }
        };
    })(),
    //*/

    {
        name: 'pajhome.org.uk',
        source: 'http://pajhome.org.uk/crypt/md5/index.html',
        size: '12K unminified',
        hash_function: 'sha256',
        compute: function(text){
            return pajhome.hex_sha256(text);
        }
    },

    (function(){
        var nacl = nacl_factory.instantiate();
        return {
            name: 'js-nacl',
            source: 'https://github.com/tonyg/js-nacl',
            size: '952K',
            hash_function: 'sha256',
            compute: function(text){
                return nacl.to_hex(nacl.crypto_hash_sha256(nacl.encode_utf8(text)));
            }
        };
    })(),

    {
        name: 'jssha256',
        source: 'http://point-at-infinity.org/jssha256/',
        hash_function: 'sha256',
        compute: function(text){
            SHA256_init();
            SHA256_write(text);
            var digest = SHA256_finalize();
            var digest_hex = array_to_hex_string(digest);
            return digest_hex;
        }
    },

    {
        name: 'chrisveness',
        source: 'https://github.com/chrisveness/crypto',
        size: '7.1K unminified',
        hash_function: 'sha256',
        compute: function(text){
            return chrisveness.hash(text);
        }
    },

    (function(){
        function decodeUTF8(s) {
            var i, d = unescape(encodeURIComponent(s)), b = new Uint8Array(d.length);
            for (i = 0; i < d.length; i++) b[i] = d.charCodeAt(i);
            return b;
        }
        return {
            name: 'blake2s',
            source: 'https://github.com/dchest/blake2s-js',
            hash_function: 'blake2',
            compute: function(text){
                var h = new BLAKE2s(32);
                h.update(decodeUTF8(text));
                return h.hexDigest();
            }
        };
    })(),

    {
        name: 'sjcl',
        source: 'https://github.com/bitwiseshiftleft/sjcl',
        size: '28K',
        hash_function: 'sha256',
        compute: function(text){
            return sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(text));
        }
    },

    {
        name: 'SO-1',
        source: 'http://stackoverflow.com/questions/18638900/javascript-crc32/18639999#18639999',
        hash_function: 'crc32',
        compute: function(text){ 
            var makeCRCTable = function(){
                var c;
                var crcTable = [];
                for(var n =0; n < 256; n++){
                    c = n;
                    for(var k =0; k < 8; k++){
                        c = ((c&1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1));
                    }
                    crcTable[n] = c;
                }
                return crcTable;
            }

            var crc32 = function(str) {
                var crcTable = window.crcTable || (window.crcTable = makeCRCTable());
                var crc = 0 ^ (-1);

                for (var i = 0; i < str.length; i++ ) {
                    crc = (crc >>> 8) ^ crcTable[(crc ^ str.charCodeAt(i)) & 0xFF];
                }

                return (crc ^ (-1)) >>> 0;
            };

            return crc32(text);
        } 
    },
    {
        name: 'SO-2',
        source: 'http://stackoverflow.com/questions/18638900/javascript-crc32/18639975#18639975',
        hash_function: 'crc32',
        compute: function(text){ 

            var a_table = "00000000 77073096 EE0E612C 990951BA 076DC419 706AF48F E963A535 9E6495A3 0EDB8832 79DCB8A4 E0D5E91E 97D2D988 09B64C2B 7EB17CBD E7B82D07 90BF1D91 1DB71064 6AB020F2 F3B97148 84BE41DE 1ADAD47D 6DDDE4EB F4D4B551 83D385C7 136C9856 646BA8C0 FD62F97A 8A65C9EC 14015C4F 63066CD9 FA0F3D63 8D080DF5 3B6E20C8 4C69105E D56041E4 A2677172 3C03E4D1 4B04D447 D20D85FD A50AB56B 35B5A8FA 42B2986C DBBBC9D6 ACBCF940 32D86CE3 45DF5C75 DCD60DCF ABD13D59 26D930AC 51DE003A C8D75180 BFD06116 21B4F4B5 56B3C423 CFBA9599 B8BDA50F 2802B89E 5F058808 C60CD9B2 B10BE924 2F6F7C87 58684C11 C1611DAB B6662D3D 76DC4190 01DB7106 98D220BC EFD5102A 71B18589 06B6B51F 9FBFE4A5 E8B8D433 7807C9A2 0F00F934 9609A88E E10E9818 7F6A0DBB 086D3D2D 91646C97 E6635C01 6B6B51F4 1C6C6162 856530D8 F262004E 6C0695ED 1B01A57B 8208F4C1 F50FC457 65B0D9C6 12B7E950 8BBEB8EA FCB9887C 62DD1DDF 15DA2D49 8CD37CF3 FBD44C65 4DB26158 3AB551CE A3BC0074 D4BB30E2 4ADFA541 3DD895D7 A4D1C46D D3D6F4FB 4369E96A 346ED9FC AD678846 DA60B8D0 44042D73 33031DE5 AA0A4C5F DD0D7CC9 5005713C 270241AA BE0B1010 C90C2086 5768B525 206F85B3 B966D409 CE61E49F 5EDEF90E 29D9C998 B0D09822 C7D7A8B4 59B33D17 2EB40D81 B7BD5C3B C0BA6CAD EDB88320 9ABFB3B6 03B6E20C 74B1D29A EAD54739 9DD277AF 04DB2615 73DC1683 E3630B12 94643B84 0D6D6A3E 7A6A5AA8 E40ECF0B 9309FF9D 0A00AE27 7D079EB1 F00F9344 8708A3D2 1E01F268 6906C2FE F762575D 806567CB 196C3671 6E6B06E7 FED41B76 89D32BE0 10DA7A5A 67DD4ACC F9B9DF6F 8EBEEFF9 17B7BE43 60B08ED5 D6D6A3E8 A1D1937E 38D8C2C4 4FDFF252 D1BB67F1 A6BC5767 3FB506DD 48B2364B D80D2BDA AF0A1B4C 36034AF6 41047A60 DF60EFC3 A867DF55 316E8EEF 4669BE79 CB61B38C BC66831A 256FD2A0 5268E236 CC0C7795 BB0B4703 220216B9 5505262F C5BA3BBE B2BD0B28 2BB45A92 5CB36A04 C2D7FFA7 B5D0CF31 2CD99E8B 5BDEAE1D 9B64C2B0 EC63F226 756AA39C 026D930A 9C0906A9 EB0E363F 72076785 05005713 95BF4A82 E2B87A14 7BB12BAE 0CB61B38 92D28E9B E5D5BE0D 7CDCEFB7 0BDBDF21 86D3D2D4 F1D4E242 68DDB3F8 1FDA836E 81BE16CD F6B9265B 6FB077E1 18B74777 88085AE6 FF0F6A70 66063BCA 11010B5C 8F659EFF F862AE69 616BFFD3 166CCF45 A00AE278 D70DD2EE 4E048354 3903B3C2 A7672661 D06016F7 4969474D 3E6E77DB AED16A4A D9D65ADC 40DF0B66 37D83BF0 A9BCAE53 DEBB9EC5 47B2CF7F 30B5FFE9 BDBDF21C CABAC28A 53B39330 24B4A3A6 BAD03605 CDD70693 54DE5729 23D967BF B3667A2E C4614AB8 5D681B02 2A6F2B94 B40BBE37 C30C8EA1 5A05DF1B 2D02EF8D";
            var b_table = a_table.split(' ').map(function(s){ return parseInt(s,16) });
            function b_crc32 (str) {
                var crc = crc ^ (-1);
                for(var i=0, iTop=str.length; i<iTop; i++) {
                    crc = ( crc >>> 8 ) ^ b_table[( crc ^ str.charCodeAt( i ) ) & 0xFF];
                }
                return (crc ^ (-1)) >>> 0;
            };

            return b_crc32(text);
        } 
    },

    {
        name: 'SO-3',
        source: 'http://stackoverflow.com/questions/8353134/javascript-crc32-function-and-php-crc32-not-matching-for-utf8/8419366#8419366',
        hash_function: 'crc32',
        compute: function(text){ 

            function Utf8Encode(string) {
                string = string.replace(/\r\n/g,"\n");
                var utftext = "";

                for (var n = 0; n < string.length; n++) {
                    var c = string.charCodeAt(n);
                    if (c < 128) {
                        utftext += String.fromCharCode(c);
                    } else if((c > 127) && (c < 2048)) {
                        utftext += String.fromCharCode((c >> 6) | 192);
                        utftext += String.fromCharCode((c & 63) | 128);
                    } else {
                        utftext += String.fromCharCode((c >> 12) | 224);
                        utftext += String.fromCharCode(((c >> 6) & 63) | 128);
                        utftext += String.fromCharCode((c & 63) | 128);
                    }
                }
                return utftext;
            };

            function crc32 (str) {
                str = Utf8Encode(str);  
                var table = "00000000 77073096 EE0E612C 990951BA 076DC419 706AF48F E963A535 9E6495A3 0EDB8832 79DCB8A4 E0D5E91E 97D2D988 09B64C2B 7EB17CBD E7B82D07 90BF1D91 1DB71064 6AB020F2 F3B97148 84BE41DE 1ADAD47D 6DDDE4EB F4D4B551 83D385C7 136C9856 646BA8C0 FD62F97A 8A65C9EC 14015C4F 63066CD9 FA0F3D63 8D080DF5 3B6E20C8 4C69105E D56041E4 A2677172 3C03E4D1 4B04D447 D20D85FD A50AB56B 35B5A8FA 42B2986C DBBBC9D6 ACBCF940 32D86CE3 45DF5C75 DCD60DCF ABD13D59 26D930AC 51DE003A C8D75180 BFD06116 21B4F4B5 56B3C423 CFBA9599 B8BDA50F 2802B89E 5F058808 C60CD9B2 B10BE924 2F6F7C87 58684C11 C1611DAB B6662D3D 76DC4190 01DB7106 98D220BC EFD5102A 71B18589 06B6B51F 9FBFE4A5 E8B8D433 7807C9A2 0F00F934 9609A88E E10E9818 7F6A0DBB 086D3D2D 91646C97 E6635C01 6B6B51F4 1C6C6162 856530D8 F262004E 6C0695ED 1B01A57B 8208F4C1 F50FC457 65B0D9C6 12B7E950 8BBEB8EA FCB9887C 62DD1DDF 15DA2D49 8CD37CF3 FBD44C65 4DB26158 3AB551CE A3BC0074 D4BB30E2 4ADFA541 3DD895D7 A4D1C46D D3D6F4FB 4369E96A 346ED9FC AD678846 DA60B8D0 44042D73 33031DE5 AA0A4C5F DD0D7CC9 5005713C 270241AA BE0B1010 C90C2086 5768B525 206F85B3 B966D409 CE61E49F 5EDEF90E 29D9C998 B0D09822 C7D7A8B4 59B33D17 2EB40D81 B7BD5C3B C0BA6CAD EDB88320 9ABFB3B6 03B6E20C 74B1D29A EAD54739 9DD277AF 04DB2615 73DC1683 E3630B12 94643B84 0D6D6A3E 7A6A5AA8 E40ECF0B 9309FF9D 0A00AE27 7D079EB1 F00F9344 8708A3D2 1E01F268 6906C2FE F762575D 806567CB 196C3671 6E6B06E7 FED41B76 89D32BE0 10DA7A5A 67DD4ACC F9B9DF6F 8EBEEFF9 17B7BE43 60B08ED5 D6D6A3E8 A1D1937E 38D8C2C4 4FDFF252 D1BB67F1 A6BC5767 3FB506DD 48B2364B D80D2BDA AF0A1B4C 36034AF6 41047A60 DF60EFC3 A867DF55 316E8EEF 4669BE79 CB61B38C BC66831A 256FD2A0 5268E236 CC0C7795 BB0B4703 220216B9 5505262F C5BA3BBE B2BD0B28 2BB45A92 5CB36A04 C2D7FFA7 B5D0CF31 2CD99E8B 5BDEAE1D 9B64C2B0 EC63F226 756AA39C 026D930A 9C0906A9 EB0E363F 72076785 05005713 95BF4A82 E2B87A14 7BB12BAE 0CB61B38 92D28E9B E5D5BE0D 7CDCEFB7 0BDBDF21 86D3D2D4 F1D4E242 68DDB3F8 1FDA836E 81BE16CD F6B9265B 6FB077E1 18B74777 88085AE6 FF0F6A70 66063BCA 11010B5C 8F659EFF F862AE69 616BFFD3 166CCF45 A00AE278 D70DD2EE 4E048354 3903B3C2 A7672661 D06016F7 4969474D 3E6E77DB AED16A4A D9D65ADC 40DF0B66 37D83BF0 A9BCAE53 DEBB9EC5 47B2CF7F 30B5FFE9 BDBDF21C CABAC28A 53B39330 24B4A3A6 BAD03605 CDD70693 54DE5729 23D967BF B3667A2E C4614AB8 5D681B02 2A6F2B94 B40BBE37 C30C8EA1 5A05DF1B 2D02EF8D";
                var crc = 0;
                var x = 0;
                var y = 0;

                crc = crc ^ (-1);
                for( var i = 0, iTop = str.length; i < iTop; i++ ) {
                    y = ( crc ^ str.charCodeAt( i ) ) & 0xFF;
                    x = "0x" + table.substr( y * 9, 8 );
                    crc = ( crc >>> 8 ) ^ x;
                }

                return (crc ^ (-1)) >>> 0;
            };

            return crc32(text);
        } 
    },

    {
        // not sure why it is asserted that `CRC32("foobar") === -1628037227`, see https://github.com/SheetJS/js-crc32/blob/f9733b16bed31eb45266ea50c495d7b8663d60df/misc/bits.js
        name: 'crc32-SheetJS',
        source: 'https://github.com/SheetJS/js-crc32', // http://sheetjs.com
        hash_function: 'crc32',
        compute: function(text){ 

            /* crc32.js (C) 2014-2015 SheetJS -- http://sheetjs.com */
            /* vim: set ts=2: */
            var CRC32;
            (function (factory) {
                if(typeof DO_NOT_EXPORT_CRC === 'undefined') {
                    if('object' === typeof exports) {
                        factory(exports);
                    } else if ('function' === typeof define && define.amd) {
                        define(function () {
                            var module = {};
                            factory(module);
                            return module;
                        });
                    } else {
                      factory(CRC32 = {});
                    }
                } else {
                    factory(CRC32 = {});
                }
            }(function(CRC32) {
            CRC32.version = '0.3.0';
            /* see perf/crc32table.js */
            function signed_crc_table() {
                var c = 0, table = new Array(256);

                for(var n =0; n != 256; ++n){
                    c = n;
                    c = ((c&1) ? (-306674912 ^ (c >>> 1)) : (c >>> 1));
                    c = ((c&1) ? (-306674912 ^ (c >>> 1)) : (c >>> 1));
                    c = ((c&1) ? (-306674912 ^ (c >>> 1)) : (c >>> 1));
                    c = ((c&1) ? (-306674912 ^ (c >>> 1)) : (c >>> 1));
                    c = ((c&1) ? (-306674912 ^ (c >>> 1)) : (c >>> 1));
                    c = ((c&1) ? (-306674912 ^ (c >>> 1)) : (c >>> 1));
                    c = ((c&1) ? (-306674912 ^ (c >>> 1)) : (c >>> 1));
                    c = ((c&1) ? (-306674912 ^ (c >>> 1)) : (c >>> 1));
                    table[n] = c;
                }

                return typeof Int32Array !== 'undefined' ? new Int32Array(table) : table;
            }

            var table = signed_crc_table();
            /* charCodeAt is the best approach for binary strings */
            var use_buffer = typeof Buffer !== 'undefined';
            function crc32_bstr(bstr) {
                if(bstr.length > 32768) if(use_buffer) return crc32_buf_8(new Buffer(bstr));
                var crc = -1, L = bstr.length - 1;
                for(var i = 0; i < L;) {
                    crc =  table[(crc ^ bstr.charCodeAt(i++)) & 0xFF] ^ (crc >>> 8);
                    crc =  table[(crc ^ bstr.charCodeAt(i++)) & 0xFF] ^ (crc >>> 8);
                }
                if(i === L) crc = (crc >>> 8) ^ table[(crc ^ bstr.charCodeAt(i)) & 0xFF];
                return crc ^ -1;
            }

            function crc32_buf(buf) {
                if(buf.length > 10000) return crc32_buf_8(buf);
                for(var crc = -1, i = 0, L=buf.length-3; i < L;) {
                    crc = (crc >>> 8) ^ table[(crc^buf[i++])&0xFF];
                    crc = (crc >>> 8) ^ table[(crc^buf[i++])&0xFF];
                    crc = (crc >>> 8) ^ table[(crc^buf[i++])&0xFF];
                    crc = (crc >>> 8) ^ table[(crc^buf[i++])&0xFF];
                }
                while(i < L+3) crc = (crc >>> 8) ^ table[(crc^buf[i++])&0xFF];
                return crc ^ -1;
            }

            function crc32_buf_8(buf) {
                for(var crc = -1, i = 0, L=buf.length-7; i < L;) {
                    crc = (crc >>> 8) ^ table[(crc^buf[i++])&0xFF];
                    crc = (crc >>> 8) ^ table[(crc^buf[i++])&0xFF];
                    crc = (crc >>> 8) ^ table[(crc^buf[i++])&0xFF];
                    crc = (crc >>> 8) ^ table[(crc^buf[i++])&0xFF];
                    crc = (crc >>> 8) ^ table[(crc^buf[i++])&0xFF];
                    crc = (crc >>> 8) ^ table[(crc^buf[i++])&0xFF];
                    crc = (crc >>> 8) ^ table[(crc^buf[i++])&0xFF];
                    crc = (crc >>> 8) ^ table[(crc^buf[i++])&0xFF];
                }
                while(i < L+7) crc = (crc >>> 8) ^ table[(crc^buf[i++])&0xFF];
                return crc ^ -1;
            }

            /* much much faster to intertwine utf8 and crc */
            function crc32_str(str) {
                for(var crc = -1, i = 0, L=str.length, c, d; i < L;) {
                    c = str.charCodeAt(i++);
                    if(c < 0x80) {
                        crc = (crc >>> 8) ^ table[(crc ^ c) & 0xFF];
                    } else if(c < 0x800) {
                        crc = (crc >>> 8) ^ table[(crc ^ (192|((c>>6)&31))) & 0xFF];
                        crc = (crc >>> 8) ^ table[(crc ^ (128|(c&63))) & 0xFF];
                    } else if(c >= 0xD800 && c < 0xE000) {
                        c = (c&1023)+64; d = str.charCodeAt(i++) & 1023;
                        crc = (crc >>> 8) ^ table[(crc ^ (240|((c>>8)&7))) & 0xFF];
                        crc = (crc >>> 8) ^ table[(crc ^ (128|((c>>2)&63))) & 0xFF];
                        crc = (crc >>> 8) ^ table[(crc ^ (128|((d>>6)&15)|(c&3))) & 0xFF];
                        crc = (crc >>> 8) ^ table[(crc ^ (128|(d&63))) & 0xFF];
                    } else {
                        crc = (crc >>> 8) ^ table[(crc ^ (224|((c>>12)&15))) & 0xFF];
                        crc = (crc >>> 8) ^ table[(crc ^ (128|((c>>6)&63))) & 0xFF];
                        crc = (crc >>> 8) ^ table[(crc ^ (128|(c&63))) & 0xFF];
                    }
                }
                return crc ^ -1;
            }
            CRC32.table = table;
            CRC32.bstr = crc32_bstr;
            CRC32.buf = crc32_buf;
            CRC32.str = crc32_str;
            }));

            return CRC32.str(text)>>>0;
        } 
    },

    {
        name: 'buffer-crc32',
        source: 'https://github.com/brianloveswords/buffer-crc32',
        hash_function: 'crc32',
        compute: function(text){ 
            return buffer_crc32.unsigned(text);
        } 
    },

    {
        name: 'crc32-brumme',
        source: 'http://create.stephan-brumme.com/crc32/#javascript',
        hash_function: 'crc32',
        compute: function(text){ 

            function Utf8Encode(string) {
                string = string.replace(/\r\n/g,"\n");
                var utftext = "";

                for (var n = 0; n < string.length; n++) {
                    var c = string.charCodeAt(n);
                    if (c < 128) {
                        utftext += String.fromCharCode(c);
                    } else if((c > 127) && (c < 2048)) {
                        utftext += String.fromCharCode((c >> 6) | 192);
                        utftext += String.fromCharCode((c & 63) | 128);
                    } else {
                        utftext += String.fromCharCode((c >> 12) | 224);
                        utftext += String.fromCharCode(((c >> 6) & 63) | 128);
                        utftext += String.fromCharCode((c & 63) | 128);
                    }
                }
                return utftext;
            };

            // //////////////////////////////////////////////////////////
            // crc32.js
            // Copyright (c) 2014 Stephan Brumme. All rights reserved.
            // see http://create.stephan-brumme.com/disclaimer.html
            //

            function hex(what)
            {
              // adjust negative numbers
              if (what < 0)
                what = 0xFFFFFFFF + what + 1;
              // convert to hexadecimal string
              var result = what.toString(16);
              // add leading zeros
              return ('0000000' + result).slice(-8);
            }

            function crc32_bitwise(text)
            {
              // CRC32b polynomial
              var Polynomial = 0xEDB88320;
              // start value
              var crc = 0xFFFFFFFF;

              for (var i = 0; i < text.length; i++)
              {
                // XOR next byte into state
                crc ^= text.charCodeAt(i);

                // process 8 bits
                for (var bit = 0; bit < 8; bit++)
                {
                  // look at lowest bit
                  if ((crc & 1) != 0)
                    crc = (crc >>> 1) ^ Polynomial;
                  else
                    crc =  crc >>> 1;
                }
              }

              return ~crc;
            }

            return crc32_bitwise(Utf8Encode(text))>>>0;
            // return crc32_bitwise(text)>>>0;
            // return parseInt(hex(crc32_bitwise(text)),16);
        } 
    },

    {
        name: 'simplycalc.com',
        source: 'http://www.simplycalc.com/crc32-source.php',
        hash_function: 'crc32',
        compute: function(text){ 
            /*
             * JavaScript CRC-32 implementation
             */

            function crc32_generate(polynomial) {
                var table = new Array()
                var i, j, n
                
                for (i = 0; i < 256; i++) {
                    n = i
                    for (j = 8; j > 0; j--) {
                        if ((n & 1) == 1) {
                            n = (n >>> 1) ^ polynomial
                        } else {
                            n = n >>> 1
                        }
                    }
                    table[i] = n
                }

                return table
            }

            function crc32_initial() {
                return 0xFFFFFFFF
            }

            function crc32_final(crc) {
                crc = ~crc
                return crc < 0 ? 0xFFFFFFFF + crc + 1 : crc
            }

            function crc32_compute_string(polynomial, str) {
                var crc = 0
                var table = crc32_generate(polynomial)
                var i
                
                crc = crc32_initial()
                
                for (i = 0; i < str.length; i++)
                    crc = (crc >>> 8) ^ table[str.charCodeAt(i) ^ (crc & 0x000000FF)]
                    
                crc = crc32_final(crc)
                return crc
            }

            function crc32_compute_buffer(polynomial, data) {
                var crc = 0
                var dataView = new DataView(data)
                var table = crc32_generate(polynomial)
                var i
                
                crc = crc32_initial()
                
                for (i = 0; i < dataView.byteLength; i++)
                    crc = (crc >>> 8) ^ table[dataView.getUint8(i) ^ (crc & 0x000000FF)]
                    
                crc = crc32_final(crc)
                return crc
            }

            return crc32_compute_string(3988292384, text);
        } 
    },

    {
        name: 'github.com/drostie/sha3-js',
        source: 'https://github.com/drostie/sha3-js',
        hash_function: 'SHA3',
        compute: function(text){ 
            var keccak32=(function(){var a=[0,10,20,5,15,16,1,11,21,6,7,17,2,12,22,23,8,18,3,13,14,24,9,19,4],R="1,8082,808a,80008000,808b,80000001,80008081,8009,8a,88,80008009,8000000a,8000808b,8b,8089,8003,8002,80,800a,8000000a,80008081,8080".split(",").map(function(i){return parseInt(i,16)}),r=[0,1,30,28,27,4,12,6,23,20,3,10,11,25,7,9,13,15,21,8,18,2,29,24,14],c=function(s,n){return(s<<n)|(s>>>(32-n))},h=function(n){return("00"+n.toString(16)).slice(-2)},o=function(n){return h(n&255)+h(n>>>8)+h(n>>>16)+h(n>>>24)};return function(m){var i,b,k,x,y,C=[],D=[],p,n=[],s;s=[];for(i=0;i<25;i++)s[i]=0;if(m.length%16==15)m+="\u8001";else{m+="\x01";while(m.length%16!=15)m+="\0";m+="\u8000"}for(b=0;b<m.length;b+=16){for(k=0;k<16;k+=2)s[k/2]^=m.charCodeAt(b+k)+m.charCodeAt(b+k+1)*65536;for(p=0;p<22;p++){for(x=0;x<5;x++)C[x]=s[x]^s[x+5]^s[x+10]^s[x+15]^s[x+20];for(x=0;x<5;x++)D[x]=C[(x+4)%5]^c(C[(x+1)%5],1);for(i=0;i<25;i++)n[a[i]]=c(s[i]^D[i%5],r[i]);for(x=0;x<5;x++)for(y=0;y<25;y+=5)s[y+x]=n[y+x]^((~n[y+(x+1)%5])&(n[y+(x+2)%5]));s[0]^=R[p]}}return s.slice(0,8).map(o).join("")}}());

            return keccak32(text);
        } 
    },

    {
        name: 'CryptoJS',
        source: 'https://code.google.com/p/crypto-js/',
        hash_function: 'SHA3',
        compute: function(text){ 
            return CryptoJS.SHA3(text, { outputLength: 256 }).toString();
        } 
    },

    {
        name: 'github.com/Yaffle',
        source: 'https://gist.github.com/Yaffle/1287361',
        hash_function: 'crc32',
        compute: function(text){ 

            function crc32(s/*, polynomial = 0x04C11DB7, initialValue = 0xFFFFFFFF, finalXORValue = 0xFFFFFFFF*/) {
              s = String(s);
              var polynomial = arguments.length < 2 ? 0x04C11DB7 : (arguments[1] >>> 0);
              var initialValue = arguments.length < 3 ? 0xFFFFFFFF : (arguments[2] >>> 0);
              var finalXORValue = arguments.length < 4 ? 0xFFFFFFFF : (arguments[3] >>> 0);
              var table = new Array(256);

              var reverse = function (x, n) {
                var b = 0;
                while (--n >= 0) {
                  b <<= 1;
                  b |= x & 1;
                  x >>>= 1;
                }
                return b;
              };

              var i = -1;
              while (++i < 256) {
                var g = reverse(i, 32);
                var j = -1;
                while (++j < 8) {
                  g = ((g << 1) ^ (((g >>> 31) & 1) * polynomial)) >>> 0;
                }
                table[i] = reverse(g, 32);
              }

              var crc = initialValue;
              var length = s.length;
              var k = -1;
              while (++k < length) {
                var c = s.charCodeAt(k);
                if (c > 255) {
                  throw new RangeError();
                }
                var index = (crc & 255) ^ c;
                crc = ((crc >>> 8) ^ table[index]) >>> 0;
              }
              return (crc ^ finalXORValue) >>> 0;
            }

            return crc32(text);
        } 
    },

]; 

export default IMPLEMENTATIONS;
