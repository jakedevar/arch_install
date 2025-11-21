import SecureRandom from './rng'
import BigInteger from './jsbn2'
import {parseBigInt} from './rsa'

/**
 * @fileinfo Keeper Modifications to JSBN RSAKey to support binary encryption/decryption.
 */

// Binary safe pkcs1 type 2 padding
function pkcs1pad2hex(hexPlaintext,n) {
  if(n < hexPlaintext.length/2 + 11) {
    alert("Message too long for RSA");
    return null;
  }
  var ba = new Array();
  var i = hexPlaintext.length;
  while(i >= 2 && n > 0) {
    ba[--n] = parseInt(hexPlaintext.slice(i-2, i), 16);
    i -= 2;
  }
  ba[--n] = 0;
  var rng = new SecureRandom();
  var x = new Array();
  while(n > 2) { // random non-zero pad
    x[0] = 0;
    while(x[0] == 0) rng.nextBytes(x);
    ba[--n] = x[0];
  }
  ba[--n] = 2;
  ba[--n] = 0;
  return new BigInteger(ba);
}

//Binary safe pkcs1 type 2 un-padding
function pkcs1unpad2hex(d,n) {
  var b = d.toByteArray();
  var i = 0;
  while(i < b.length && b[i] == 0) ++i;
  if(b.length-i != n-1 || b[i] != 2)
    return null;
  ++i;
  while(b[i] != 0)
    if(++i >= b.length) return null;
  var ret = "";
  while(++i < b.length) {
    var c = b[i] & 255;
    ret += (c < 16) ? '0' + c.toString(16) : c.toString(16);
  }
  return ret;
}

/**
 * Generates a ASN.1 Hex string.
 * @param {boolean} include_private Set to true to include the private bits as well.
 * @returns
 */
export function RSAtoASN1Hex (include_private) {
  var v = asn('00');
  var n = asn(this.n.toString(16));
  var e = asn(this.e.toString(16));
  var d = asn(this.d.toString(16));
  var p = asn(this.p.toString(16));
  var q = asn(this.q.toString(16));
  var dmp1 = asn(this.dmp1.toString(16));
  var dmq1 = asn(this.dmq1.toString(16));
  var coeff = asn(this.coeff.toString(16));

  if (typeof include_private !== 'undefined' && include_private)
    return asn(v + n + e + d + p + q + dmp1 + dmq1 + coeff, '30');
  else
    return asn(n + e, '30');


  function asn (data, type) {
    if (typeof type === 'undefined') type = '02';

    // Pad the data with a leading '0' if necessary
    data = (data.length % 2 === 0) ? data : '0' + data;

    // Pad the data again with a '00' to ensure its positive.  Some parser 
    // stupid implementations will freak out on negative RSA bits.
    if (parseInt(data.substr(0,2), 16) > 127)
      data = '00' + data;

    return type + asn_length(data) + data;
  }

  function asn_length (item) {
    var length = item.length / 2;   // We're dealing with hex here
    var length_hex = (length.toString(16).length % 2 === 0) ? length.toString(16) : '0' + length.toString(16);

    if (length < 128) {
      return length_hex;
    } else {
      var length_length = 128 + length_hex.length / 2;
      var length_length_hex = (length_length.toString(16).length % 2 === 0) ? length_length.toString(16) : '0' + length_length.toString(16);

      return length_length_hex + length_hex;
    }
  }
}

/**
 * Encrypts hex input with this RSA key
 * @param {string} hex 
 * @returns {string}
 */
export function RSAEncryptBinary(hex) {
  var m = pkcs1pad2hex(hex,(this.n.bitLength()+7)>>3);
  if(m == null) return null;
  var c = this.doPublic(m);
  if(c == null) return null;
  var h = c.toString(16);
  if((h.length & 1) == 0) return h; else return "0" + h;
}

/**
 * Decrypt ciphertext with this RSA key 
 * @param {string | Uint8Array} ctext 
 * @returns 
 */
export function RSADecryptBinary(ctext) {
  var c = parseBigInt(ctext, 16);
  var m = this.doPrivate(c);
  if(m == null) return null;
  return pkcs1unpad2hex(m, (this.n.bitLength()+7)>>3);
}