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
    // computed with sha256sum of GNU coreutils
    'three.min.js': '1f7805e0870ff94285773806bccc88fa4c992a159b02aa5288e070f1356d3836',
    'jquery-2.1.4.min.js': 'f16ab224bb962910558715c82f58c10c3ed20f153ddfaa199029f141b5b0255c',
    'angular.min.js': '79ff1591234ea9434d7f96516781130625b1880ba4fa8eb965b278337e11f8ae',
    'react-0.13.3.min.js': 'a9cabcd164e8e495c28685591c7d2e4d9cab95a8daff1c52abf9be221fffd74f',
    'd3.min.js': 'c641285840b6477b0e5da33c8e768a4f8de0ba80b24db92218016b6ad8fdc754',
    'raphael-min.js': 'df8ebbd8b4047589534140d324b9b55a3c6bf1651e847ed1a9ef9c8a82b472ea',
    'moment-with-locales.min.js': 'f828fba78735e7a4148eecda050132f08449b67c65e0583f7466a9b75deba686',
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
                var color = algo.hash.toString() === LIBS_HASH[lib] ? 'black' : 'red';
                if( algo.name === 'blake2s' ) color = 'grey';
                result_row.innerHTML = `<td>${algo.execTime}</td><td>${algo.name}</td><td style='color: ${color}'>${algo.hash}</td>`;
                table.appendChild(result_row);

            }

        }

}
