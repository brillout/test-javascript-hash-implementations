// not tried -- would require to extract sha256 algorithm from test script
// https://github.com/Kukunin/asm.js-benchmark

// benchmark
// https://github.com/dominictarr/crypto-bench
// http://dominictarr.github.io/crypto-bench/


// https://github.com/crypto-browserify/sha.js
import createHash from 'sha.js';

// http://pajhome.org.uk/crypt/md5/index.html
// 12K unminified
import pajhome from 'algos/pajhome_sha256';

// http://anmar.eu.org/projects/jssha2/
// 3.6K unminified
import jssha2 from 'algos/jsSha2/sha256';

// https://github.com/digitalbazaar/forge
import forge from 'algos/forge.min';

// https://github.com/chrisveness/crypto
// 7.1K unminified
import chrisveness from 'algos/chrisveness_sha256';

// https://github.com/dchest/blake2s-js
// 12K
import BLAKE2s from 'algos/blake2s.min';

// https://github.com/brianloveswords/buffer-crc32
import buffer_crc32 from 'buffer-crc32';



const ALGOS = [ 
    // https://github.com/digitalbazaar/forge
    // 284K
    (function(){
        function wide_char_exists(str){
            for( var i = 0; i < str.length; i++ ){
                if ( str.charCodeAt(i) >>> 8 ) return true;
            }
            return false;
        }

        return {
            name: 'forge [conditional UTF8]',
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
        compute: function(text){
            var md = forge.md.sha256.create();
            md.update(text);
            return md.digest().toHex();
        }
    },
    {
        name: 'forge [UTF8]',
        compute: function(text){
            var md = forge.md.sha256.create();
            md.update(text, 'utf8');
            return md.digest().toHex();
        }
    },

    // http://anmar.eu.org/projects/jssha2/
    // 3.6K unminified
    {
        name: 'jssha2',
        compute: function(text){
            return jssha2.hex_sha256(text);
        }
    },

    // https://github.com/vibornoff/asmcrypto.js
    {
        name: 'asmCrypto',
        compute: function(text){
            return asmCrypto.SHA256.hex(text);
        }
    },

    // https://github.com/crypto-browserify/sha.js
    {
        name: 'crypto-browserify/sha.js',
        compute: function(text) {
            var sha = createHash('sha256');
            return sha.update(text,'utf8').digest('hex');
        }
    },

    // https://code.google.com/p/crypto-js/
    // 16K
    {
        name: 'CryptoJS',
        compute: function(text){
            return CryptoJS.SHA256(text);
        }
    },

    // https://github.com/sitegui/pbkdf-sha256-asm
    /* can't make it work
    (function(){
        var sha = Module.cwrap('sha_simple', 'string', ['string']);
        return {
            name: 'pbkdf-sha256-asm',
            compute: function(text){
                return sha(text);
            }
        };
    })(),
    //*/

    // http://pajhome.org.uk/crypt/md5/index.html
    // 12K unminified
    {
        name: 'pajhome.org.uk',
        compute: function(text){
            return pajhome.hex_sha256(text);
        }
    },

    // https://github.com/tonyg/js-nacl
    // 952K
    (function(){
        var nacl = nacl_factory.instantiate();
        return {
            name: 'js-nacl',
            compute: function(text){
                return nacl.to_hex(nacl.crypto_hash_sha256(nacl.encode_utf8(text)));
            }
        };
    })(),

    // http://point-at-infinity.org/jssha256/
    {
        name: 'jssha256',
        compute: function(text){
            SHA256_init();
            SHA256_write(text);
            var digest = SHA256_finalize();
            var digest_hex = array_to_hex_string(digest);
            return digest_hex;
        }
    },

    // https://github.com/chrisveness/crypto
    // 7.1K unminified
    {
        name: 'chrisveness',
        compute: function(text){
            return chrisveness.hash(text);
        }
    },

    // https://github.com/dchest/blake2s-js
    (function(){
        function decodeUTF8(s) {
            var i, d = unescape(encodeURIComponent(s)), b = new Uint8Array(d.length);
            for (i = 0; i < d.length; i++) b[i] = d.charCodeAt(i);
            return b;
        }
        return {
            name: 'blake2s',
            hash_type: 'blake2',
            compute: function(text){
                var h = new BLAKE2s(32);
                h.update(decodeUTF8(text));
                return h.hexDigest();
            }
        };
    })(),

    // https://github.com/bitwiseshiftleft/sjcl
    // 28K
    {
        name: 'sjcl',
        compute: function(text){
            return sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(text));
        }
    },

    // http://stackoverflow.com/questions/18638900/javascript-crc32
    {
        name: 'crc32-SO-1',
        hash_type: 'crc32',
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
        name: 'crc32-SO-2',
        hash_type: 'crc32',
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
        name: 'crc32-SO-3',
        hash_type: 'crc32',
        compute: function(text){ 

            var crc32 = (function()
            {
                var table = new Uint32Array(256);

                // Pre-generate crc32 polynomial lookup table
                // http://wiki.osdev.org/CRC32#Building_the_Lookup_Table
                // ... Actually use Alex's because it generates the correct bit order
                //     so no need for the reversal function
                for(var i=256; i--;)
                {
                    var tmp = i;

                    for(var k=8; k--;)
                    {
                        tmp = tmp & 1 ? 3988292384 ^ tmp >>> 1 : tmp >>> 1;
                    }

                    table[i] = tmp;
                }

                // crc32b
                // Example input        : [97, 98, 99, 100, 101] (Uint8Array)
                // Example output       : 2240272485 (Uint32)
                return function( data )
                {
                    var crc = -1; // Begin with all bits set ( 0xffffffff )

                    for(var i=0, l=data.length; i<l; i++)
                    {
                        crc = crc >>> 8 ^ table[ crc & 255 ^ data[i] ];
                    }

                    return (crc ^ -1) >>> 0; // Apply binary NOT
                };

            })();

            return crc32(text);
        } 
    },

    // http://stackoverflow.com/questions/8353134/javascript-crc32-function-and-php-crc32-not-matching-for-utf8/8419366#8419366
    {
        name: 'crc32-SO-4',
        hash_type: 'crc32',
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

    // http://sheetjs.com, https://github.com/SheetJS/js-crc32
    // not sure why it is asserted that `CRC32("foobar") === -1628037227`, see https://github.com/SheetJS/js-crc32/blob/f9733b16bed31eb45266ea50c495d7b8663d60df/misc/bits.js
    {
        name: 'crc32-SheetJS',
        hash_type: 'crc32',
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

            return CRC32.str(text);
        } 
    },

    // https://github.com/brianloveswords/buffer-crc32
    {
        name: 'buffer-crc32',
        hash_type: 'crc32',
        compute: function(text){ 
            return buffer_crc32(text);
        } 
    },

]; 

const LIBS = [ 
    'three.min.js',
    'jquery-2.1.4.min.js',
    'angular.min.js',
    'react-0.13.3.min.js',
    'd3.min.js',
    'raphael-min.js',
    'moment-with-locales.min.js',
]; 

const LIBS_HASH = { 
    // computed with `sha256sum` cli of GNU coreutils
    'three.min.js': '1f7805e0870ff94285773806bccc88fa4c992a159b02aa5288e070f1356d3836',
    'jquery-2.1.4.min.js': 'f16ab224bb962910558715c82f58c10c3ed20f153ddfaa199029f141b5b0255c',
    'angular.min.js': '79ff1591234ea9434d7f96516781130625b1880ba4fa8eb965b278337e11f8ae',
    'react-0.13.3.min.js': 'a9cabcd164e8e495c28685591c7d2e4d9cab95a8daff1c52abf9be221fffd74f',
    'd3.min.js': 'c641285840b6477b0e5da33c8e768a4f8de0ba80b24db92218016b6ad8fdc754',
    'raphael-min.js': 'df8ebbd8b4047589534140d324b9b55a3c6bf1651e847ed1a9ef9c8a82b472ea',
    'moment-with-locales.min.js': 'f828fba78735e7a4148eecda050132f08449b67c65e0583f7466a9b75deba686',
}; 

const LIBS_CHECKSUM = {
    // computed with `crc32` cli of Archive::Zip module for Perl, `apt-get install libarchive-zip-perl`
    'angular.min.js':             '9a1f3172',
    'd3.min.js':                  '31ebc13b',
    'jquery-2.1.4.min.js':        'cc381312',
    'moment-with-locales.min.js': '52728fcd',
    'raphael-min.js':             'c983bc25',
    'react-0.13.3.min.js':        '32fec3ab',
    'three.min.js':               'dda42dce',
};

function req(url, callback) { 

    var req = new XMLHttpRequest();

    req.onreadystatechange = function(){
        if ( req.readyState === 4 ) {
            callback(req.responseText);
        }
    };

    req.open('GET',url);

    req.send();

} 


(function(){

    var results = {};
    for(var lib of LIBS) {
        results[lib] = {};
        for(var algo of ALGOS) {
            results[lib][algo.name] = {};
        }
    }

    var source_codes = {};

    var n_resp_count = 0;

    LIBS.forEach(function(lib){
        req('libs/'+lib, function(source_code){

            ALGOS.forEach(function(algo){

                var execTime;
                var hash;

                var past = new Date();

                try{
                    hash = algo.compute(source_code);
                    execTime = new Date() - past;
                }
                catch(e){
                    hash = e.toString();
                    execTime = '-';
                }

                source_codes[lib] = source_code;

                results[lib][algo.name] = {
                    name: algo.name,
                    hash: hash,
                    execTime: execTime,
                    hash_is_correct: (function(){
                        if( algo.hash_type === 'blake2' ) return null;
                        var reference_arr = algo.hash_type === 'crc32' && LIBS_CHECKSUM || LIBS_HASH;
                        var reference_val = algo.hash_type === 'crc32' && parseInt(reference_arr[lib],16) || reference_arr[lib];
                        return hash === reference_val;
                    })(),
                };

            });

            if( ++n_resp_count === LIBS.length ) print_results(results, source_codes);
        });
    });

})();

var out = document.getElementById("results");
out.innerHTML = 'computing';

function print_results(results, source_codes){

        out.innerHTML = "";

        for(var lib in results) {

            var title = document.createElement("h3");
            title.innerHTML = "Time to compute SHA-256 hash of "+lib+" (~"+Math.round(source_codes[lib].length/1000)+"KB)";

            var table = document.createElement("table");
            var header = document.createElement("tr");
            header.innerHTML = "<td>time (ms)</td><td>algorithm</td><td>hash</td>";
            table.appendChild(header);

            out.appendChild(title);
            out.appendChild(table);

            for(var algo_name in results[lib]) {

                var algo = results[lib][algo_name];

                var result_row = document.createElement("tr");
                var color = algo.hash_is_correct && 'black' || algo.hash_is_correct===false && 'red' || 'grey';
                result_row.innerHTML = `<td>${algo.execTime}</td><td>${algo.name}</td><td style='color: ${color}'>${algo.hash}</td>`;
                table.appendChild(result_row);

            }

        }

}
