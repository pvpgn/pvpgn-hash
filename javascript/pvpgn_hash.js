/**
* JavaScript implementation of the PvPGN Password Hash Algorithm.
* Copyright 2011 Naki-BoT (naki@pvpgn.pl)
* http://naki.info/
* 
* This code is available under the GNU Lesser General Public License:
* http://www.gnu.org/licenses/lgpl.txt
* 
* This code in general is based on:
* Copyright 2004 Aaron (aaron@pvpgn.org)
* PHP implementation of the PvPGN Password Hash Algorithm
* Copyright 2002 - 2003 Marcus Campbell
* http://www.tecknik.net/sha-1/
* Based on the JavaScript SHA-1 implementation by Paul Johnston
* http://pajhome.org.uk/
* the safe_rol function is taken from an PHP SHA-1 implementation
* written by Chris Monson (chris@bouncingchairs.net)
* Most recent version available on http://bouncingchairs.net
* (Based on the SHA algorithm as given in "Applied Cryptography")
*/
var pvpgn_hash = function() {
    var ord_unicode = function(chr) {
        // JavaScript charCodeAt() function returns Unicode of the character
        unicode = chr.charCodeAt(0);
        if(unicode <= 0x7F) {
            return [unicode];
        }
        else if(unicode < 0x80) {
            return false;
        }
        else if(unicode <= 0x7FF) {
            binary = str_pad_left(decbin(unicode),11);
            return [
                bindec("110" + binary.substr(0,5)),
                bindec("10" + binary.substr(5))
            ];
        }
        else if(unicode <= 0xFFFF) {
            binary = str_pad_left(decbin(unicode),16);
            return [
                bindec("1110" + binary.substr(0,4)),
                bindec("10" + binary.substr(4,6)),
                bindec("10" + binary.substr(10))
            ];
        }
        else if(unicode <= 0x1FFFFF) {
            binary = str_pad_left(decbin(unicode),21);
            return [
                bindec("11110" + binary.substr(0,3)),
                bindec("10" + binary.substr(3,6)),
                bindec("10" + binary.substr(9,6)),
                bindec("10" + binary.substr(15))
            ];
        }
        else {
            return false;
        }
    };
    var str_pad_left = function(number,length) {
        if(number.length < length) {
            for(var i = number.length;i < length;i++) {
                number = "0" + number;
            }
        }
        return number;
    };
    var str2blks_pvpgn = function(str) {
        nblk = ((str.length + 8) >> 6) + 1;
        var blks = [];
        for(var i = 0; i < nblk * 16; i++) {
            blks[i] = 0;
        }
        for(var i = 0,j = 0; i < str.length; i++) {
            var unicode = ord_unicode(str.charAt(i));
            if(typeof unicode === "object") {
                for(var k = 0; k < unicode.length; k++) {
                    blks[j >> 2] |= unicode[k] << ((j % 4) * 8);
                    j++;
                }
            }
        }
        return blks;
    };
    var safe_add = function(x,y) {
        lsw = (x & 0xFFFF) + (y & 0xFFFF);
        msw = (x >> 16) + (y >> 16) + (lsw >> 16);
        return (msw << 16) | (lsw & 0xFFFF);
    };
    var safe_not = function(num) {
        lsw = (~(num & 0xFFFF)) & 0xFFFF;
        msw = (~(num >> 16)) & 0xFFFF;
        return (msw << 16) | lsw;
    };
    var safe_rol = function(num,amt) {
        leftmask = 0xffff | (0xffff << 16);
        leftmask <<= 32 - amt;
        rightmask = 0xffff | (0xffff << 16);
        rightmask <<= amt;
        rightmask = safe_not(rightmask);

        remains = num & leftmask;
        remains >>= 32 - amt;
        remains &= rightmask;

        res = (num << amt) | remains;
        return res;
    };
    var ft = function(t,b,c,d) {
        if(t < 20) {
            return (b & c) | ((safe_not(b)) & d);
        }
        if(t < 40) {
            return d ^ c ^ b;
        }
        if(t < 60) {
            return (c & b) | (d & c) | (d & b);
        }
        return d ^ c ^ b;
    };
    var kt = function(t) {
        if(t < 20) {
            return 0x5a82 << 16 | 0x7999;
        }
        else if(t < 40) {
            return 0x6ed9 << 16 | 0xeba1;
        }
        else if(t < 60) {
            return 0x8f1b << 16 | 0xbcdc;
        }
        else {
            return 0xca62 << 16 | 0xc1d6;
        }
    };
    var pvpgn_hash = function(str,decode_html_entities) {
        // Convert special HTML entities back to characters: "&gt;" -> ">" etc.
        if(decode_html_entities) {
            str = htmlspecialchars_decode(str,"ENT_QUOTES");
        }

        // Unicode support
        for(var i = 0;i < str.length; i++) {
            // PvPGN hash is case insensitive but only for ASCII characters
            if(str.charCodeAt(i) < 128) {
                str = str.substr(0,i) + str.charAt(i).toLowerCase() + str.substr(i + 1);
            }
        }

        x = str2blks_pvpgn(str);

        a = 0x6745 << 16 | 0x2301;
        b = 0xefcd << 16 | 0xab89;
        c = 0x98ba << 16 | 0xdcfe;
        d = 0x1032 << 16 | 0x5476;
        e = 0xc3d2 << 16 | 0xe1f0;    

        for(var i = 0; i < x.length; i += 16) {
            olda = a;
            oldb = b;
            oldc = c;
            oldd = d;
            olde = e;

            var w = [];
            for(var j = 0; j < 16; j++) {
                w[j] = x[i + j];
            }

            for(var j = 0; j < 64; j++) {
                ww = w[j] ^ w[j + 8] ^ w[j + 2] ^ w[j + 13];
                w[j + 16] = 1 << (ww % 32);
            }

            for(var j = 0; j < 80; j++) {
                if(j < 20) {
                    t = safe_add(safe_add(safe_rol(a,5),ft(j,b,c,d)),safe_add(safe_add(e,w[j]),kt(j)));
                }
                else {
                    t = safe_add(safe_add(safe_rol(t,5),ft(j,b,c,d)),safe_add(safe_add(e,w[j]),kt(j)));
                }

                e = d;
                d = c;
                c = safe_rol(b,30);
                b = a;
                a = t;
            }

            a = safe_add(t,olda);
            b = safe_add(b,oldb);
            c = safe_add(c,oldc);
            d = safe_add(d,oldd);
            e = safe_add(e,olde);
        }

        // Fix for 64-bit OS by Pada
        a = str_pad_left(dechex(a & 0xffffffff),8);
        b = str_pad_left(dechex(b & 0xffffffff),8);
        c = str_pad_left(dechex(c & 0xffffffff),8);
        d = str_pad_left(dechex(d & 0xffffffff),8);
        e = str_pad_left(dechex(e & 0xffffffff),8);
        return a + b + c + d + e;
    };
    // http://kevin.vanzonneveld.net
    var htmlspecialchars_decode = function(string,quote_style) {
        var optTemp = 0, i = 0, noquotes= false;
        if(typeof quote_style === "undefined") {
            quote_style = 2;
        }
        string = string.toString().replace(/&lt;/g,"<").replace(/&gt;/g,">");
        var OPTS = {
            'ENT_NOQUOTES': 0,
            'ENT_HTML_QUOTE_SINGLE' : 1,
            'ENT_HTML_QUOTE_DOUBLE' : 2,
            'ENT_COMPAT': 2,
            'ENT_QUOTES': 3,
            'ENT_IGNORE' : 4
        };
        if(quote_style === 0) {
            noquotes = true;
        }
        if(typeof quote_style !== "number") {
            quote_style = [].concat(quote_style);
            for(i = 0; i < quote_style.length; i++) {
                // Resolve string input to bitwise e.g. 'PATHINFO_EXTENSION' becomes 4
                if (OPTS[quote_style[i]] === 0) {
                    noquotes = true;
                }
                else if (OPTS[quote_style[i]]) {
                    optTemp = optTemp | OPTS[quote_style[i]];
                }
            }
            quote_style = optTemp;
        }
        if(quote_style & OPTS.ENT_HTML_QUOTE_SINGLE) {
             // PHP doesn't currently escape if more than one 0, but it should
            string = string.replace(/&#0*39;/g,"'");
            // This would also be useful here, but not a part of PHP
            // string = string.replace(/&apos;|&#x0*27;/g,"'");
        }
        if(!noquotes) {
            string = string.replace(/&quot;/g,'"');
        }
        // Put this in last place to avoid escape being double-decoded
        string = string.replace(/&amp;/g,"&");

        return string;
    };
    // http://kevin.vanzonneveld.net
    var decbin = function(number) {
        if(number < 0) {
            number = 0xFFFFFFFF + number + 1;
        }
        return parseInt(number, 10).toString(2);
    };
    // http://kevin.vanzonneveld.net
    var bindec = function(binary_string) {
        binary_string = (binary_string + "").replace(/[^01]/gi,"");
        return parseInt(binary_string, 2);
    };
    // http://kevin.vanzonneveld.net
    var dechex = function(number) {
        if(number < 0) {
            number = 0xFFFFFFFF + number + 1;
        }
        return parseInt(number,10).toString(16);
    };
    return {
        get_hash: function(str,decode_html_entities) {
            return pvpgn_hash(str,decode_html_entities);
        }
    };
}();