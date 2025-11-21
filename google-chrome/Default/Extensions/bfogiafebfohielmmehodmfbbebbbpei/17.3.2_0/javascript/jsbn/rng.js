import {prng_newstate, rng_psize} from "./prng4";

(function () {

  // For best results, put code like
  // <body onClick='rng_seed_time();' onKeyPress='rng_seed_time();'>
  // in your main HTML document.

  var rng_state;
  var rng_pool;
  var rng_pptr;

  // Mix in a 32-bit integer into the pool
  function rng_seed_int(x) {
    rng_pool[rng_pptr++] ^= x & 255;
    rng_pool[rng_pptr++] ^= (x >> 8) & 255;
    rng_pool[rng_pptr++] ^= (x >> 16) & 255;
    rng_pool[rng_pptr++] ^= (x >> 24) & 255;
    if(rng_pptr >= rng_psize) rng_pptr -= rng_psize;
  }

  // Mix in the current time (w/milliseconds) into the pool
  function rng_seed_time() {
    rng_seed_int(new Date().getTime());
  }

  var crypto = self.crypto || self.msCrypto;
  var webCryptoSupported = crypto && crypto.getRandomValues;

  // Initialize the pool with junk if needed.
  if (rng_pool == null) {
    rng_pool = new Array();
    var t;
    if (webCryptoSupported) {
      // Use webcrypto if available
      var ua = new Uint8Array(rng_psize);
      crypto.getRandomValues(ua);
      for(t = 0; t < rng_psize; t++)
        rng_pool[t] = ua[t];
    }
    rng_seed_time();
    //rng_seed_int(self.screenX);
    //rng_seed_int(self.screenY);
  }

  function rng_get_byte() {
    if(rng_state == null) {
      rng_seed_time();
      rng_state = prng_newstate();
      rng_state.init(rng_pool);
      for(rng_pptr = 0; rng_pptr < rng_pool.length; ++rng_pptr)
        rng_pool[rng_pptr] = 0;
      rng_pptr = 0;
      //rng_pool = null;
    }
    // TODO: allow reseeding after first request
    return rng_state.next();
  }

  function rng_get_bytes(ba) {
    var i;
    for(i = 0; i < ba.length; ++i) ba[i] = rng_get_byte();
  }

  function not_secure() {
    throw new Error('Your browser does not support crypto secure PRNG');
  }

  SecureRandom.prototype.nextBytes = webCryptoSupported ? rng_get_bytes : not_secure;

}());

function SecureRandom() {}

export default SecureRandom