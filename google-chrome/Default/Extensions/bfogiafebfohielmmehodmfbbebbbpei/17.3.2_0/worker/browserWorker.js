(function () {
    'use strict';

    class KeyWrapper {
        static create(key) {
            const wrapper = new KeyWrapper();
            wrapper.key = key;
            return wrapper;
        }
        getKey() {
            return this.key;
        }
    }
    function connectPlatform(p) {
        platform = p;
    }
    let platform;

    class CryptoWorkerPool {
        constructor(config) {
            this.workers = [];
            this.config = config;
        }
        async open() {
            while (this.workers.length < this.config.numThreads) {
                const worker = await this.config.createWorker();
                this.workers.push(worker);
            }
        }
        async close() {
            for (let worker of this.workers) {
                await worker.terminate();
            }
            this.workers.length = 0;
        }
        async getKeys(tasks) {
            const keys = {};
            for (const task of tasks) {
                const { keyId, encryptionType } = task;
                if (keys[keyId])
                    continue;
                try {
                    keys[keyId] = await this.config.getKey(keyId, encryptionType);
                }
                catch (e) {
                    console.error(e);
                }
            }
            return keys;
        }
        async runTasks(tasks) {
            // Split into chunks for each worker
            const numberOfItems = tasks.length;
            const chunkSize = Math.ceil(numberOfItems / this.workers.length);
            const chunks = this.chunk(tasks, chunkSize);
            // Issue concurrent requests
            const chunkedResults = await Promise.all(chunks.map(async (chunk, index) => {
                const worker = this.workers[index];
                const keys = await this.getKeys(chunk);
                return worker.sendMessage({
                    data: chunk,
                    keys
                });
            }));
            // Merge and return results
            return Object.assign({}, ...chunkedResults);
        }
        chunk(array, chunkSize) {
            const chunks = [];
            while (array.length) {
                // Important note: Array.splice drains the input array,
                // but faster than Array.slice
                chunks.push(array.splice(0, chunkSize));
            }
            return chunks;
        }
    }
    async function handleCryptoWorkerMessage(message) {
        const { data, keys } = message;
        const keyStorage = {
            getKeyBytes: async (keyId) => {
                return keys[keyId];
            },
            saveKeyBytes: async (_keyId, _key) => {
                // unused
            }
        };
        let results = {};
        await Promise.all(data.map(async (task) => {
            const { data, dataId, keyId, encryptionType } = task;
            try {
                const keyBytes = await platform.decrypt(data, keyId, encryptionType, keyStorage);
                results[dataId] = keyBytes;
            }
            catch (e) {
                console.error(`The key ${dataId} cannot be decrypted (${e.message})`);
            }
        }));
        return results;
    }

    // @ts-nocheck
    // Copyright (c) 2005  Tom Wu
    // All Rights Reserved.
    // See "LICENSE" for details.
    // Basic JavaScript BN library - subset useful for RSA encryption.
    // Bits per digit
    var dbits;
    // (public) Constructor
    function BigInteger(a, b, c) {
        if (a != null)
            if ("number" == typeof a)
                this.fromNumber(a, b, c);
            else if (b == null && "string" != typeof a)
                this.fromString(a, 256);
            else
                this.fromString(a, b);
    }
    // convert a (hex) string to a bignum object
    function parseBigInt(str, r) {
        return new BigInteger(str, r);
    }
    // return new, unset BigInteger
    function nbi() { return new BigInteger(); }
    // am: Compute w_j += (x*this_i), propagate carries,
    // c is initial carry, returns final carry.
    // c < 3*dvalue, x < 2*dvalue, this_i < dvalue
    // We need to select the fastest one that works in this environment.
    // am1: use a single mult and divide to get the high bits,
    // max digit bits should be 26 because
    // max internal value = 2*dvalue^2-2*dvalue (< 2^53)
    function am1(i, x, w, j, c, n) {
        while (--n >= 0) {
            var v = x * this[i++] + w[j] + c;
            c = Math.floor(v / 0x4000000);
            w[j++] = v & 0x3ffffff;
        }
        return c;
    }
    // am2 avoids a big mult-and-extract completely.
    // Max digit bits should be <= 30 because we do bitwise ops
    // on values up to 2*hdvalue^2-hdvalue-1 (< 2^31)
    function am2(i, x, w, j, c, n) {
        var xl = x & 0x7fff, xh = x >> 15;
        while (--n >= 0) {
            var l = this[i] & 0x7fff;
            var h = this[i++] >> 15;
            var m = xh * l + h * xl;
            l = xl * l + ((m & 0x7fff) << 15) + w[j] + (c & 0x3fffffff);
            c = (l >>> 30) + (m >>> 15) + xh * h + (c >>> 30);
            w[j++] = l & 0x3fffffff;
        }
        return c;
    }
    // Alternately, set max digit bits to 28 since some
    // browsers slow down when dealing with 32-bit numbers.
    function am3(i, x, w, j, c, n) {
        var xl = x & 0x3fff, xh = x >> 14;
        while (--n >= 0) {
            var l = this[i] & 0x3fff;
            var h = this[i++] >> 14;
            var m = xh * l + h * xl;
            l = xl * l + ((m & 0x3fff) << 14) + w[j] + c;
            c = (l >> 28) + (m >> 14) + xh * h;
            w[j++] = l & 0xfffffff;
        }
        return c;
    }
    if ((typeof (navigator) !== 'undefined') && (navigator.appName == "Microsoft Internet Explorer")) {
        BigInteger.prototype.am = am2;
        dbits = 30;
    }
    else if ((typeof (navigator) !== 'undefined') && (navigator.appName != "Netscape")) {
        BigInteger.prototype.am = am1;
        dbits = 26;
    }
    else { // Mozilla/Netscape seems to prefer am3
        BigInteger.prototype.am = am3;
        dbits = 28;
    }
    BigInteger.prototype.DB = dbits;
    BigInteger.prototype.DM = ((1 << dbits) - 1);
    BigInteger.prototype.DV = (1 << dbits);
    var BI_FP = 52;
    BigInteger.prototype.FV = Math.pow(2, BI_FP);
    BigInteger.prototype.F1 = BI_FP - dbits;
    BigInteger.prototype.F2 = 2 * dbits - BI_FP;
    // Digit conversions
    var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
    var BI_RC = new Array();
    var rr, vv;
    rr = "0".charCodeAt(0);
    for (vv = 0; vv <= 9; ++vv)
        BI_RC[rr++] = vv;
    rr = "a".charCodeAt(0);
    for (vv = 10; vv < 36; ++vv)
        BI_RC[rr++] = vv;
    rr = "A".charCodeAt(0);
    for (vv = 10; vv < 36; ++vv)
        BI_RC[rr++] = vv;
    function int2char(n) { return BI_RM.charAt(n); }
    function intAt(s, i) {
        var c = BI_RC[s.charCodeAt(i)];
        return (c == null) ? -1 : c;
    }
    // (protected) copy this to r
    function bnpCopyTo(r) {
        for (var i = this.t - 1; i >= 0; --i)
            r[i] = this[i];
        r.t = this.t;
        r.s = this.s;
    }
    // (protected) set from integer value x, -DV <= x < DV
    function bnpFromInt(x) {
        this.t = 1;
        this.s = (x < 0) ? -1 : 0;
        if (x > 0)
            this[0] = x;
        else if (x < -1)
            this[0] = x + this.DV;
        else
            this.t = 0;
    }
    // return bigint initialized to value
    function nbv(i) { var r = nbi(); r.fromInt(i); return r; }
    // (protected) set from string and radix
    function bnpFromString(s, b) {
        var k;
        if (b == 16)
            k = 4;
        else if (b == 8)
            k = 3;
        else if (b == 256)
            k = 8; // byte array
        else if (b == 2)
            k = 1;
        else if (b == 32)
            k = 5;
        else if (b == 4)
            k = 2;
        else {
            this.fromRadix(s, b);
            return;
        }
        this.t = 0;
        this.s = 0;
        var i = s.length, mi = false, sh = 0;
        while (--i >= 0) {
            var x = (k == 8) ? s[i] & 0xff : intAt(s, i);
            if (x < 0) {
                if (s.charAt(i) == "-")
                    mi = true;
                continue;
            }
            mi = false;
            if (sh == 0)
                this[this.t++] = x;
            else if (sh + k > this.DB) {
                this[this.t - 1] |= (x & ((1 << (this.DB - sh)) - 1)) << sh;
                this[this.t++] = (x >> (this.DB - sh));
            }
            else
                this[this.t - 1] |= x << sh;
            sh += k;
            if (sh >= this.DB)
                sh -= this.DB;
        }
        if (k == 8 && (s[0] & 0x80) != 0) {
            this.s = -1;
            if (sh > 0)
                this[this.t - 1] |= ((1 << (this.DB - sh)) - 1) << sh;
        }
        this.clamp();
        if (mi)
            ZERO.subTo(this, this);
    }
    // (protected) clamp off excess high words
    function bnpClamp() {
        var c = this.s & this.DM;
        while (this.t > 0 && this[this.t - 1] == c)
            --this.t;
    }
    // (public) return string representation in given radix
    function bnToString(b) {
        if (this.s < 0)
            return "-" + this.negate().toString(b);
        var k;
        if (b == 16)
            k = 4;
        else if (b == 8)
            k = 3;
        else if (b == 2)
            k = 1;
        else if (b == 32)
            k = 5;
        else if (b == 4)
            k = 2;
        else
            return this.toRadix(b);
        var km = (1 << k) - 1, d, m = false, r = "", i = this.t;
        var p = this.DB - (i * this.DB) % k;
        if (i-- > 0) {
            if (p < this.DB && (d = this[i] >> p) > 0) {
                m = true;
                r = int2char(d);
            }
            while (i >= 0) {
                if (p < k) {
                    d = (this[i] & ((1 << p) - 1)) << (k - p);
                    d |= this[--i] >> (p += this.DB - k);
                }
                else {
                    d = (this[i] >> (p -= k)) & km;
                    if (p <= 0) {
                        p += this.DB;
                        --i;
                    }
                }
                if (d > 0)
                    m = true;
                if (m)
                    r += int2char(d);
            }
        }
        return m ? r : "0";
    }
    // (public) -this
    function bnNegate() { var r = nbi(); ZERO.subTo(this, r); return r; }
    // (public) |this|
    function bnAbs() { return (this.s < 0) ? this.negate() : this; }
    // (public) return + if this > a, - if this < a, 0 if equal
    function bnCompareTo(a) {
        var r = this.s - a.s;
        if (r != 0)
            return r;
        var i = this.t;
        r = i - a.t;
        if (r != 0)
            return (this.s < 0) ? -r : r;
        while (--i >= 0)
            if ((r = this[i] - a[i]) != 0)
                return r;
        return 0;
    }
    // returns bit length of the integer x
    function nbits(x) {
        var r = 1, t;
        if ((t = x >>> 16) != 0) {
            x = t;
            r += 16;
        }
        if ((t = x >> 8) != 0) {
            x = t;
            r += 8;
        }
        if ((t = x >> 4) != 0) {
            x = t;
            r += 4;
        }
        if ((t = x >> 2) != 0) {
            x = t;
            r += 2;
        }
        if ((t = x >> 1) != 0) {
            x = t;
            r += 1;
        }
        return r;
    }
    // (public) return the number of bits in "this"
    function bnBitLength() {
        if (this.t <= 0)
            return 0;
        return this.DB * (this.t - 1) + nbits(this[this.t - 1] ^ (this.s & this.DM));
    }
    // (protected) r = this << n*DB
    function bnpDLShiftTo(n, r) {
        var i;
        for (i = this.t - 1; i >= 0; --i)
            r[i + n] = this[i];
        for (i = n - 1; i >= 0; --i)
            r[i] = 0;
        r.t = this.t + n;
        r.s = this.s;
    }
    // (protected) r = this >> n*DB
    function bnpDRShiftTo(n, r) {
        for (var i = n; i < this.t; ++i)
            r[i - n] = this[i];
        r.t = Math.max(this.t - n, 0);
        r.s = this.s;
    }
    // (protected) r = this << n
    function bnpLShiftTo(n, r) {
        var bs = n % this.DB;
        var cbs = this.DB - bs;
        var bm = (1 << cbs) - 1;
        var ds = Math.floor(n / this.DB), c = (this.s << bs) & this.DM, i;
        for (i = this.t - 1; i >= 0; --i) {
            r[i + ds + 1] = (this[i] >> cbs) | c;
            c = (this[i] & bm) << bs;
        }
        for (i = ds - 1; i >= 0; --i)
            r[i] = 0;
        r[ds] = c;
        r.t = this.t + ds + 1;
        r.s = this.s;
        r.clamp();
    }
    // (protected) r = this >> n
    function bnpRShiftTo(n, r) {
        r.s = this.s;
        var ds = Math.floor(n / this.DB);
        if (ds >= this.t) {
            r.t = 0;
            return;
        }
        var bs = n % this.DB;
        var cbs = this.DB - bs;
        var bm = (1 << bs) - 1;
        r[0] = this[ds] >> bs;
        for (var i = ds + 1; i < this.t; ++i) {
            r[i - ds - 1] |= (this[i] & bm) << cbs;
            r[i - ds] = this[i] >> bs;
        }
        if (bs > 0)
            r[this.t - ds - 1] |= (this.s & bm) << cbs;
        r.t = this.t - ds;
        r.clamp();
    }
    // (protected) r = this - a
    function bnpSubTo(a, r) {
        var i = 0, c = 0, m = Math.min(a.t, this.t);
        while (i < m) {
            c += this[i] - a[i];
            r[i++] = c & this.DM;
            c >>= this.DB;
        }
        if (a.t < this.t) {
            c -= a.s;
            while (i < this.t) {
                c += this[i];
                r[i++] = c & this.DM;
                c >>= this.DB;
            }
            c += this.s;
        }
        else {
            c += this.s;
            while (i < a.t) {
                c -= a[i];
                r[i++] = c & this.DM;
                c >>= this.DB;
            }
            c -= a.s;
        }
        r.s = (c < 0) ? -1 : 0;
        if (c < -1)
            r[i++] = this.DV + c;
        else if (c > 0)
            r[i++] = c;
        r.t = i;
        r.clamp();
    }
    // (protected) r = this * a, r != this,a (HAC 14.12)
    // "this" should be the larger one if appropriate.
    function bnpMultiplyTo(a, r) {
        var x = this.abs(), y = a.abs();
        var i = x.t;
        r.t = i + y.t;
        while (--i >= 0)
            r[i] = 0;
        for (i = 0; i < y.t; ++i)
            r[i + x.t] = x.am(0, y[i], r, i, 0, x.t);
        r.s = 0;
        r.clamp();
        if (this.s != a.s)
            ZERO.subTo(r, r);
    }
    // (protected) r = this^2, r != this (HAC 14.16)
    function bnpSquareTo(r) {
        var x = this.abs();
        var i = r.t = 2 * x.t;
        while (--i >= 0)
            r[i] = 0;
        for (i = 0; i < x.t - 1; ++i) {
            var c = x.am(i, x[i], r, 2 * i, 0, 1);
            if ((r[i + x.t] += x.am(i + 1, 2 * x[i], r, 2 * i + 1, c, x.t - i - 1)) >= x.DV) {
                r[i + x.t] -= x.DV;
                r[i + x.t + 1] = 1;
            }
        }
        if (r.t > 0)
            r[r.t - 1] += x.am(i, x[i], r, 2 * i, 0, 1);
        r.s = 0;
        r.clamp();
    }
    // (protected) divide this by m, quotient and remainder to q, r (HAC 14.20)
    // r != q, this != m.  q or r may be null.
    function bnpDivRemTo(m, q, r) {
        var pm = m.abs();
        if (pm.t <= 0)
            return;
        var pt = this.abs();
        if (pt.t < pm.t) {
            if (q != null)
                q.fromInt(0);
            if (r != null)
                this.copyTo(r);
            return;
        }
        if (r == null)
            r = nbi();
        var y = nbi(), ts = this.s, ms = m.s;
        var nsh = this.DB - nbits(pm[pm.t - 1]); // normalize modulus
        if (nsh > 0) {
            pm.lShiftTo(nsh, y);
            pt.lShiftTo(nsh, r);
        }
        else {
            pm.copyTo(y);
            pt.copyTo(r);
        }
        var ys = y.t;
        var y0 = y[ys - 1];
        if (y0 == 0)
            return;
        var yt = y0 * (1 << this.F1) + ((ys > 1) ? y[ys - 2] >> this.F2 : 0);
        var d1 = this.FV / yt, d2 = (1 << this.F1) / yt, e = 1 << this.F2;
        var i = r.t, j = i - ys, t = (q == null) ? nbi() : q;
        y.dlShiftTo(j, t);
        if (r.compareTo(t) >= 0) {
            r[r.t++] = 1;
            r.subTo(t, r);
        }
        ONE.dlShiftTo(ys, t);
        t.subTo(y, y); // "negative" y so we can replace sub with am later
        while (y.t < ys)
            y[y.t++] = 0;
        while (--j >= 0) {
            // Estimate quotient digit
            var qd = (r[--i] == y0) ? this.DM : Math.floor(r[i] * d1 + (r[i - 1] + e) * d2);
            if ((r[i] += y.am(0, qd, r, j, 0, ys)) < qd) { // Try it out
                y.dlShiftTo(j, t);
                r.subTo(t, r);
                while (r[i] < --qd)
                    r.subTo(t, r);
            }
        }
        if (q != null) {
            r.drShiftTo(ys, q);
            if (ts != ms)
                ZERO.subTo(q, q);
        }
        r.t = ys;
        r.clamp();
        if (nsh > 0)
            r.rShiftTo(nsh, r); // Denormalize remainder
        if (ts < 0)
            ZERO.subTo(r, r);
    }
    // (public) this mod a
    function bnMod(a) {
        var r = nbi();
        this.abs().divRemTo(a, null, r);
        if (this.s < 0 && r.compareTo(ZERO) > 0)
            a.subTo(r, r);
        return r;
    }
    // Modular reduction using "classic" algorithm
    function Classic(m) { this.m = m; }
    function cConvert(x) {
        if (x.s < 0 || x.compareTo(this.m) >= 0)
            return x.mod(this.m);
        else
            return x;
    }
    function cRevert(x) { return x; }
    function cReduce(x) { x.divRemTo(this.m, null, x); }
    function cMulTo(x, y, r) { x.multiplyTo(y, r); this.reduce(r); }
    function cSqrTo(x, r) { x.squareTo(r); this.reduce(r); }
    Classic.prototype.convert = cConvert;
    Classic.prototype.revert = cRevert;
    Classic.prototype.reduce = cReduce;
    Classic.prototype.mulTo = cMulTo;
    Classic.prototype.sqrTo = cSqrTo;
    // (protected) return "-1/this % 2^DB"; useful for Mont. reduction
    // justification:
    //         xy == 1 (mod m)
    //         xy =  1+km
    //   xy(2-xy) = (1+km)(1-km)
    // x[y(2-xy)] = 1-k^2m^2
    // x[y(2-xy)] == 1 (mod m^2)
    // if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
    // should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
    // JS multiply "overflows" differently from C/C++, so care is needed here.
    function bnpInvDigit() {
        if (this.t < 1)
            return 0;
        var x = this[0];
        if ((x & 1) == 0)
            return 0;
        var y = x & 3; // y == 1/x mod 2^2
        y = (y * (2 - (x & 0xf) * y)) & 0xf; // y == 1/x mod 2^4
        y = (y * (2 - (x & 0xff) * y)) & 0xff; // y == 1/x mod 2^8
        y = (y * (2 - (((x & 0xffff) * y) & 0xffff))) & 0xffff; // y == 1/x mod 2^16
        // last step - calculate inverse mod DV directly;
        // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
        y = (y * (2 - x * y % this.DV)) % this.DV; // y == 1/x mod 2^dbits
        // we really want the negative inverse, and -DV < y < DV
        return (y > 0) ? this.DV - y : -y;
    }
    // Montgomery reduction
    function Montgomery(m) {
        this.m = m;
        this.mp = m.invDigit();
        this.mpl = this.mp & 0x7fff;
        this.mph = this.mp >> 15;
        this.um = (1 << (m.DB - 15)) - 1;
        this.mt2 = 2 * m.t;
    }
    // xR mod m
    function montConvert(x) {
        var r = nbi();
        x.abs().dlShiftTo(this.m.t, r);
        r.divRemTo(this.m, null, r);
        if (x.s < 0 && r.compareTo(ZERO) > 0)
            this.m.subTo(r, r);
        return r;
    }
    // x/R mod m
    function montRevert(x) {
        var r = nbi();
        x.copyTo(r);
        this.reduce(r);
        return r;
    }
    // x = x/R mod m (HAC 14.32)
    function montReduce(x) {
        while (x.t <= this.mt2) // pad x so am has enough room later
            x[x.t++] = 0;
        for (var i = 0; i < this.m.t; ++i) {
            // faster way of calculating u0 = x[i]*mp mod DV
            var j = x[i] & 0x7fff;
            var u0 = (j * this.mpl + (((j * this.mph + (x[i] >> 15) * this.mpl) & this.um) << 15)) & x.DM;
            // use am to combine the multiply-shift-add into one call
            j = i + this.m.t;
            x[j] += this.m.am(0, u0, x, i, 0, this.m.t);
            // propagate carry
            while (x[j] >= x.DV) {
                x[j] -= x.DV;
                x[++j]++;
            }
        }
        x.clamp();
        x.drShiftTo(this.m.t, x);
        if (x.compareTo(this.m) >= 0)
            x.subTo(this.m, x);
    }
    // r = "x^2/R mod m"; x != r
    function montSqrTo(x, r) { x.squareTo(r); this.reduce(r); }
    // r = "xy/R mod m"; x,y != r
    function montMulTo(x, y, r) { x.multiplyTo(y, r); this.reduce(r); }
    Montgomery.prototype.convert = montConvert;
    Montgomery.prototype.revert = montRevert;
    Montgomery.prototype.reduce = montReduce;
    Montgomery.prototype.mulTo = montMulTo;
    Montgomery.prototype.sqrTo = montSqrTo;
    // (protected) true iff this is even
    function bnpIsEven() { return ((this.t > 0) ? (this[0] & 1) : this.s) == 0; }
    // (protected) this^e, e < 2^32, doing sqr and mul with "r" (HAC 14.79)
    function bnpExp(e, z) {
        if (e > 0xffffffff || e < 1)
            return ONE;
        var r = nbi(), r2 = nbi(), g = z.convert(this), i = nbits(e) - 1;
        g.copyTo(r);
        while (--i >= 0) {
            z.sqrTo(r, r2);
            if ((e & (1 << i)) > 0)
                z.mulTo(r2, g, r);
            else {
                var t = r;
                r = r2;
                r2 = t;
            }
        }
        return z.revert(r);
    }
    // (public) this^e % m, 0 <= e < 2^32
    function bnModPowInt(e, m) {
        var z;
        if (e < 256 || m.isEven())
            z = new Classic(m);
        else
            z = new Montgomery(m);
        return this.exp(e, z);
    }
    // jsbn2
    // Extended JavaScript BN functions, required for RSA private ops.
    // Version 1.1: new BigInteger("0", 10) returns "proper" zero
    // Version 1.2: square() API, isProbablePrime fix
    // (public)
    function bnClone() { var r = nbi(); this.copyTo(r); return r; }
    // (public) return value as integer
    function bnIntValue() {
        if (this.s < 0) {
            if (this.t == 1)
                return this[0] - this.DV;
            else if (this.t == 0)
                return -1;
        }
        else if (this.t == 1)
            return this[0];
        else if (this.t == 0)
            return 0;
        // assumes 16 < DB < 32
        return ((this[1] & ((1 << (32 - this.DB)) - 1)) << this.DB) | this[0];
    }
    // (public) return value as byte
    function bnByteValue() { return (this.t == 0) ? this.s : (this[0] << 24) >> 24; }
    // (public) return value as short (assumes DB>=16)
    function bnShortValue() { return (this.t == 0) ? this.s : (this[0] << 16) >> 16; }
    // (protected) return x s.t. r^x < DV
    function bnpChunkSize(r) { return Math.floor(Math.LN2 * this.DB / Math.log(r)); }
    // (public) 0 if this == 0, 1 if this > 0
    function bnSigNum() {
        if (this.s < 0)
            return -1;
        else if (this.t <= 0 || (this.t == 1 && this[0] <= 0))
            return 0;
        else
            return 1;
    }
    // (protected) convert to radix string
    function bnpToRadix(b) {
        if (b == null)
            b = 10;
        if (this.signum() == 0 || b < 2 || b > 36)
            return "0";
        var cs = this.chunkSize(b);
        var a = Math.pow(b, cs);
        var d = nbv(a), y = nbi(), z = nbi(), r = "";
        this.divRemTo(d, y, z);
        while (y.signum() > 0) {
            r = (a + z.intValue()).toString(b).substr(1) + r;
            y.divRemTo(d, y, z);
        }
        return z.intValue().toString(b) + r;
    }
    // (protected) convert from radix string
    function bnpFromRadix(s, b) {
        this.fromInt(0);
        if (b == null)
            b = 10;
        var cs = this.chunkSize(b);
        var d = Math.pow(b, cs), mi = false, j = 0, w = 0;
        for (var i = 0; i < s.length; ++i) {
            var x = intAt(s, i);
            if (x < 0) {
                if (s.charAt(i) == "-" && this.signum() == 0)
                    mi = true;
                continue;
            }
            w = b * w + x;
            if (++j >= cs) {
                this.dMultiply(d);
                this.dAddOffset(w, 0);
                j = 0;
                w = 0;
            }
        }
        if (j > 0) {
            this.dMultiply(Math.pow(b, j));
            this.dAddOffset(w, 0);
        }
        if (mi)
            ZERO.subTo(this, this);
    }
    // (protected) alternate constructor
    function bnpFromNumber(a, b, c) {
        if ("number" == typeof b) {
            // new BigInteger(int,int,RNG)
            if (a < 2)
                this.fromInt(1);
            else {
                this.fromNumber(a, c);
                if (!this.testBit(a - 1)) // force MSB set
                    this.bitwiseTo(ONE.shiftLeft(a - 1), op_or, this);
                if (this.isEven())
                    this.dAddOffset(1, 0); // force odd
                while (!this.isProbablePrime(b)) {
                    this.dAddOffset(2, 0);
                    if (this.bitLength() > a)
                        this.subTo(ONE.shiftLeft(a - 1), this);
                }
            }
        }
        else {
            // new BigInteger(int,RNG)
            var x = new Array(), t = a & 7;
            x.length = (a >> 3) + 1;
            b.nextBytes(x);
            if (t > 0)
                x[0] &= ((1 << t) - 1);
            else
                x[0] = 0;
            this.fromString(x, 256);
        }
    }
    // (public) convert to bigendian byte array
    function bnToByteArray() {
        var i = this.t, r = new Array();
        r[0] = this.s;
        var p = this.DB - (i * this.DB) % 8, d, k = 0;
        if (i-- > 0) {
            if (p < this.DB && (d = this[i] >> p) != (this.s & this.DM) >> p)
                r[k++] = d | (this.s << (this.DB - p));
            while (i >= 0) {
                if (p < 8) {
                    d = (this[i] & ((1 << p) - 1)) << (8 - p);
                    d |= this[--i] >> (p += this.DB - 8);
                }
                else {
                    d = (this[i] >> (p -= 8)) & 0xff;
                    if (p <= 0) {
                        p += this.DB;
                        --i;
                    }
                }
                if ((d & 0x80) != 0)
                    d |= -256;
                if (k == 0 && (this.s & 0x80) != (d & 0x80))
                    ++k;
                if (k > 0 || d != this.s)
                    r[k++] = d;
            }
        }
        return r;
    }
    function bnEquals(a) { return (this.compareTo(a) == 0); }
    function bnMin(a) { return (this.compareTo(a) < 0) ? this : a; }
    function bnMax(a) { return (this.compareTo(a) > 0) ? this : a; }
    // (protected) r = this op a (bitwise)
    function bnpBitwiseTo(a, op, r) {
        var i, f, m = Math.min(a.t, this.t);
        for (i = 0; i < m; ++i)
            r[i] = op(this[i], a[i]);
        if (a.t < this.t) {
            f = a.s & this.DM;
            for (i = m; i < this.t; ++i)
                r[i] = op(this[i], f);
            r.t = this.t;
        }
        else {
            f = this.s & this.DM;
            for (i = m; i < a.t; ++i)
                r[i] = op(f, a[i]);
            r.t = a.t;
        }
        r.s = op(this.s, a.s);
        r.clamp();
    }
    // (public) this & a
    function op_and(x, y) { return x & y; }
    function bnAnd(a) { var r = nbi(); this.bitwiseTo(a, op_and, r); return r; }
    // (public) this | a
    function op_or(x, y) { return x | y; }
    function bnOr(a) { var r = nbi(); this.bitwiseTo(a, op_or, r); return r; }
    // (public) this ^ a
    function op_xor(x, y) { return x ^ y; }
    function bnXor(a) { var r = nbi(); this.bitwiseTo(a, op_xor, r); return r; }
    // (public) this & ~a
    function op_andnot(x, y) { return x & ~y; }
    function bnAndNot(a) { var r = nbi(); this.bitwiseTo(a, op_andnot, r); return r; }
    // (public) ~this
    function bnNot() {
        var r = nbi();
        for (var i = 0; i < this.t; ++i)
            r[i] = this.DM & ~this[i];
        r.t = this.t;
        r.s = ~this.s;
        return r;
    }
    // (public) this << n
    function bnShiftLeft(n) {
        var r = nbi();
        if (n < 0)
            this.rShiftTo(-n, r);
        else
            this.lShiftTo(n, r);
        return r;
    }
    // (public) this >> n
    function bnShiftRight(n) {
        var r = nbi();
        if (n < 0)
            this.lShiftTo(-n, r);
        else
            this.rShiftTo(n, r);
        return r;
    }
    // return index of lowest 1-bit in x, x < 2^31
    function lbit(x) {
        if (x == 0)
            return -1;
        var r = 0;
        if ((x & 0xffff) == 0) {
            x >>= 16;
            r += 16;
        }
        if ((x & 0xff) == 0) {
            x >>= 8;
            r += 8;
        }
        if ((x & 0xf) == 0) {
            x >>= 4;
            r += 4;
        }
        if ((x & 3) == 0) {
            x >>= 2;
            r += 2;
        }
        if ((x & 1) == 0)
            ++r;
        return r;
    }
    // (public) returns index of lowest 1-bit (or -1 if none)
    function bnGetLowestSetBit() {
        for (var i = 0; i < this.t; ++i)
            if (this[i] != 0)
                return i * this.DB + lbit(this[i]);
        if (this.s < 0)
            return this.t * this.DB;
        return -1;
    }
    // return number of 1 bits in x
    function cbit(x) {
        var r = 0;
        while (x != 0) {
            x &= x - 1;
            ++r;
        }
        return r;
    }
    // (public) return number of set bits
    function bnBitCount() {
        var r = 0, x = this.s & this.DM;
        for (var i = 0; i < this.t; ++i)
            r += cbit(this[i] ^ x);
        return r;
    }
    // (public) true iff nth bit is set
    function bnTestBit(n) {
        var j = Math.floor(n / this.DB);
        if (j >= this.t)
            return (this.s != 0);
        return ((this[j] & (1 << (n % this.DB))) != 0);
    }
    // (protected) this op (1<<n)
    function bnpChangeBit(n, op) {
        var r = ONE.shiftLeft(n);
        this.bitwiseTo(r, op, r);
        return r;
    }
    // (public) this | (1<<n)
    function bnSetBit(n) { return this.changeBit(n, op_or); }
    // (public) this & ~(1<<n)
    function bnClearBit(n) { return this.changeBit(n, op_andnot); }
    // (public) this ^ (1<<n)
    function bnFlipBit(n) { return this.changeBit(n, op_xor); }
    // (protected) r = this + a
    function bnpAddTo(a, r) {
        var i = 0, c = 0, m = Math.min(a.t, this.t);
        while (i < m) {
            c += this[i] + a[i];
            r[i++] = c & this.DM;
            c >>= this.DB;
        }
        if (a.t < this.t) {
            c += a.s;
            while (i < this.t) {
                c += this[i];
                r[i++] = c & this.DM;
                c >>= this.DB;
            }
            c += this.s;
        }
        else {
            c += this.s;
            while (i < a.t) {
                c += a[i];
                r[i++] = c & this.DM;
                c >>= this.DB;
            }
            c += a.s;
        }
        r.s = (c < 0) ? -1 : 0;
        if (c > 0)
            r[i++] = c;
        else if (c < -1)
            r[i++] = this.DV + c;
        r.t = i;
        r.clamp();
    }
    // (public) this + a
    function bnAdd(a) { var r = nbi(); this.addTo(a, r); return r; }
    // (public) this - a
    function bnSubtract(a) { var r = nbi(); this.subTo(a, r); return r; }
    // (public) this * a
    function bnMultiply(a) { var r = nbi(); this.multiplyTo(a, r); return r; }
    // (public) this^2
    function bnSquare() { var r = nbi(); this.squareTo(r); return r; }
    // (public) this / a
    function bnDivide(a) { var r = nbi(); this.divRemTo(a, r, null); return r; }
    // (public) this % a
    function bnRemainder(a) { var r = nbi(); this.divRemTo(a, null, r); return r; }
    // (public) [this/a,this%a]
    function bnDivideAndRemainder(a) {
        var q = nbi(), r = nbi();
        this.divRemTo(a, q, r);
        return new Array(q, r);
    }
    // (protected) this *= n, this >= 0, 1 < n < DV
    function bnpDMultiply(n) {
        this[this.t] = this.am(0, n - 1, this, 0, 0, this.t);
        ++this.t;
        this.clamp();
    }
    // (protected) this += n << w words, this >= 0
    function bnpDAddOffset(n, w) {
        if (n == 0)
            return;
        while (this.t <= w)
            this[this.t++] = 0;
        this[w] += n;
        while (this[w] >= this.DV) {
            this[w] -= this.DV;
            if (++w >= this.t)
                this[this.t++] = 0;
            ++this[w];
        }
    }
    // A "null" reducer
    function NullExp() { }
    function nNop(x) { return x; }
    function nMulTo(x, y, r) { x.multiplyTo(y, r); }
    function nSqrTo(x, r) { x.squareTo(r); }
    NullExp.prototype.convert = nNop;
    NullExp.prototype.revert = nNop;
    NullExp.prototype.mulTo = nMulTo;
    NullExp.prototype.sqrTo = nSqrTo;
    // (public) this^e
    function bnPow(e) { return this.exp(e, new NullExp()); }
    // (protected) r = lower n words of "this * a", a.t <= n
    // "this" should be the larger one if appropriate.
    function bnpMultiplyLowerTo(a, n, r) {
        var i = Math.min(this.t + a.t, n);
        r.s = 0; // assumes a,this >= 0
        r.t = i;
        while (i > 0)
            r[--i] = 0;
        var j;
        for (j = r.t - this.t; i < j; ++i)
            r[i + this.t] = this.am(0, a[i], r, i, 0, this.t);
        for (j = Math.min(a.t, n); i < j; ++i)
            this.am(0, a[i], r, i, 0, n - i);
        r.clamp();
    }
    // (protected) r = "this * a" without lower n words, n > 0
    // "this" should be the larger one if appropriate.
    function bnpMultiplyUpperTo(a, n, r) {
        --n;
        var i = r.t = this.t + a.t - n;
        r.s = 0; // assumes a,this >= 0
        while (--i >= 0)
            r[i] = 0;
        for (i = Math.max(n - this.t, 0); i < a.t; ++i)
            r[this.t + i - n] = this.am(n - i, a[i], r, 0, 0, this.t + i - n);
        r.clamp();
        r.drShiftTo(1, r);
    }
    // Barrett modular reduction
    function Barrett(m) {
        // setup Barrett
        this.r2 = nbi();
        this.q3 = nbi();
        ONE.dlShiftTo(2 * m.t, this.r2);
        this.mu = this.r2.divide(m);
        this.m = m;
    }
    function barrettConvert(x) {
        if (x.s < 0 || x.t > 2 * this.m.t)
            return x.mod(this.m);
        else if (x.compareTo(this.m) < 0)
            return x;
        else {
            var r = nbi();
            x.copyTo(r);
            this.reduce(r);
            return r;
        }
    }
    function barrettRevert(x) { return x; }
    // x = x mod m (HAC 14.42)
    function barrettReduce(x) {
        x.drShiftTo(this.m.t - 1, this.r2);
        if (x.t > this.m.t + 1) {
            x.t = this.m.t + 1;
            x.clamp();
        }
        this.mu.multiplyUpperTo(this.r2, this.m.t + 1, this.q3);
        this.m.multiplyLowerTo(this.q3, this.m.t + 1, this.r2);
        while (x.compareTo(this.r2) < 0)
            x.dAddOffset(1, this.m.t + 1);
        x.subTo(this.r2, x);
        while (x.compareTo(this.m) >= 0)
            x.subTo(this.m, x);
    }
    // r = x^2 mod m; x != r
    function barrettSqrTo(x, r) { x.squareTo(r); this.reduce(r); }
    // r = x*y mod m; x,y != r
    function barrettMulTo(x, y, r) { x.multiplyTo(y, r); this.reduce(r); }
    Barrett.prototype.convert = barrettConvert;
    Barrett.prototype.revert = barrettRevert;
    Barrett.prototype.reduce = barrettReduce;
    Barrett.prototype.mulTo = barrettMulTo;
    Barrett.prototype.sqrTo = barrettSqrTo;
    // (public) this^e % m (HAC 14.85)
    function bnModPow(e, m) {
        var i = e.bitLength(), k, r = nbv(1), z;
        if (i <= 0)
            return r;
        else if (i < 18)
            k = 1;
        else if (i < 48)
            k = 3;
        else if (i < 144)
            k = 4;
        else if (i < 768)
            k = 5;
        else
            k = 6;
        if (i < 8)
            z = new Classic(m);
        else if (m.isEven())
            z = new Barrett(m);
        else
            z = new Montgomery(m);
        // precomputation
        var g = new Array(), n = 3, k1 = k - 1, km = (1 << k) - 1;
        g[1] = z.convert(this);
        if (k > 1) {
            var g2 = nbi();
            z.sqrTo(g[1], g2);
            while (n <= km) {
                g[n] = nbi();
                z.mulTo(g2, g[n - 2], g[n]);
                n += 2;
            }
        }
        var j = e.t - 1, w, is1 = true, r2 = nbi(), t;
        i = nbits(e[j]) - 1;
        while (j >= 0) {
            if (i >= k1)
                w = (e[j] >> (i - k1)) & km;
            else {
                w = (e[j] & ((1 << (i + 1)) - 1)) << (k1 - i);
                if (j > 0)
                    w |= e[j - 1] >> (this.DB + i - k1);
            }
            n = k;
            while ((w & 1) == 0) {
                w >>= 1;
                --n;
            }
            if ((i -= n) < 0) {
                i += this.DB;
                --j;
            }
            if (is1) { // ret == 1, don't bother squaring or multiplying it
                g[w].copyTo(r);
                is1 = false;
            }
            else {
                while (n > 1) {
                    z.sqrTo(r, r2);
                    z.sqrTo(r2, r);
                    n -= 2;
                }
                if (n > 0)
                    z.sqrTo(r, r2);
                else {
                    t = r;
                    r = r2;
                    r2 = t;
                }
                z.mulTo(r2, g[w], r);
            }
            while (j >= 0 && (e[j] & (1 << i)) == 0) {
                z.sqrTo(r, r2);
                t = r;
                r = r2;
                r2 = t;
                if (--i < 0) {
                    i = this.DB - 1;
                    --j;
                }
            }
        }
        return z.revert(r);
    }
    // (public) gcd(this,a) (HAC 14.54)
    function bnGCD(a) {
        var x = (this.s < 0) ? this.negate() : this.clone();
        var y = (a.s < 0) ? a.negate() : a.clone();
        if (x.compareTo(y) < 0) {
            var t = x;
            x = y;
            y = t;
        }
        var i = x.getLowestSetBit(), g = y.getLowestSetBit();
        if (g < 0)
            return x;
        if (i < g)
            g = i;
        if (g > 0) {
            x.rShiftTo(g, x);
            y.rShiftTo(g, y);
        }
        while (x.signum() > 0) {
            if ((i = x.getLowestSetBit()) > 0)
                x.rShiftTo(i, x);
            if ((i = y.getLowestSetBit()) > 0)
                y.rShiftTo(i, y);
            if (x.compareTo(y) >= 0) {
                x.subTo(y, x);
                x.rShiftTo(1, x);
            }
            else {
                y.subTo(x, y);
                y.rShiftTo(1, y);
            }
        }
        if (g > 0)
            y.lShiftTo(g, y);
        return y;
    }
    // (protected) this % n, n < 2^26
    function bnpModInt(n) {
        if (n <= 0)
            return 0;
        var d = this.DV % n, r = (this.s < 0) ? n - 1 : 0;
        if (this.t > 0)
            if (d == 0)
                r = this[0] % n;
            else
                for (var i = this.t - 1; i >= 0; --i)
                    r = (d * r + this[i]) % n;
        return r;
    }
    // (public) 1/this % m (HAC 14.61)
    function bnModInverse(m) {
        var ac = m.isEven();
        if ((this.isEven() && ac) || m.signum() == 0)
            return ZERO;
        var u = m.clone(), v = this.clone();
        var a = nbv(1), b = nbv(0), c = nbv(0), d = nbv(1);
        while (u.signum() != 0) {
            while (u.isEven()) {
                u.rShiftTo(1, u);
                if (ac) {
                    if (!a.isEven() || !b.isEven()) {
                        a.addTo(this, a);
                        b.subTo(m, b);
                    }
                    a.rShiftTo(1, a);
                }
                else if (!b.isEven())
                    b.subTo(m, b);
                b.rShiftTo(1, b);
            }
            while (v.isEven()) {
                v.rShiftTo(1, v);
                if (ac) {
                    if (!c.isEven() || !d.isEven()) {
                        c.addTo(this, c);
                        d.subTo(m, d);
                    }
                    c.rShiftTo(1, c);
                }
                else if (!d.isEven())
                    d.subTo(m, d);
                d.rShiftTo(1, d);
            }
            if (u.compareTo(v) >= 0) {
                u.subTo(v, u);
                if (ac)
                    a.subTo(c, a);
                b.subTo(d, b);
            }
            else {
                v.subTo(u, v);
                if (ac)
                    c.subTo(a, c);
                d.subTo(b, d);
            }
        }
        if (v.compareTo(ONE) != 0)
            return ZERO;
        if (d.compareTo(m) >= 0)
            return d.subtract(m);
        if (d.signum() < 0)
            d.addTo(m, d);
        else
            return d;
        if (d.signum() < 0)
            return d.add(m);
        else
            return d;
    }
    var lowprimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997];
    var lplim = (1 << 26) / lowprimes[lowprimes.length - 1];
    // (public) test primality with certainty >= 1-.5^t
    function bnIsProbablePrime(t) {
        var i, x = this.abs();
        if (x.t == 1 && x[0] <= lowprimes[lowprimes.length - 1]) {
            for (i = 0; i < lowprimes.length; ++i)
                if (x[0] == lowprimes[i])
                    return true;
            return false;
        }
        if (x.isEven())
            return false;
        i = 1;
        while (i < lowprimes.length) {
            var m = lowprimes[i], j = i + 1;
            while (j < lowprimes.length && m < lplim)
                m *= lowprimes[j++];
            m = x.modInt(m);
            while (i < j)
                if (m % lowprimes[i++] == 0)
                    return false;
        }
        return x.millerRabin(t);
    }
    // (protected) true if probably prime (HAC 4.24, Miller-Rabin)
    function bnpMillerRabin(t) {
        var n1 = this.subtract(ONE);
        var k = n1.getLowestSetBit();
        if (k <= 0)
            return false;
        var r = n1.shiftRight(k);
        t = (t + 1) >> 1;
        if (t > lowprimes.length)
            t = lowprimes.length;
        var a = nbi();
        for (var i = 0; i < t; ++i) {
            //Pick bases at random, instead of starting at 2
            a.fromInt(lowprimes[Math.floor(Math.random() * lowprimes.length)]);
            var y = a.modPow(r, this);
            if (y.compareTo(ONE) != 0 && y.compareTo(n1) != 0) {
                var j = 1;
                while (j++ < k && y.compareTo(n1) != 0) {
                    y = y.modPowInt(2, this);
                    if (y.compareTo(ONE) == 0)
                        return false;
                }
                if (y.compareTo(n1) != 0)
                    return false;
            }
        }
        return true;
    }
    // protected
    BigInteger.prototype.copyTo = bnpCopyTo;
    BigInteger.prototype.fromInt = bnpFromInt;
    BigInteger.prototype.fromString = bnpFromString;
    BigInteger.prototype.clamp = bnpClamp;
    BigInteger.prototype.dlShiftTo = bnpDLShiftTo;
    BigInteger.prototype.drShiftTo = bnpDRShiftTo;
    BigInteger.prototype.lShiftTo = bnpLShiftTo;
    BigInteger.prototype.rShiftTo = bnpRShiftTo;
    BigInteger.prototype.subTo = bnpSubTo;
    BigInteger.prototype.multiplyTo = bnpMultiplyTo;
    BigInteger.prototype.squareTo = bnpSquareTo;
    BigInteger.prototype.divRemTo = bnpDivRemTo;
    BigInteger.prototype.invDigit = bnpInvDigit;
    BigInteger.prototype.isEven = bnpIsEven;
    BigInteger.prototype.exp = bnpExp;
    // public
    BigInteger.prototype.toString = bnToString;
    BigInteger.prototype.negate = bnNegate;
    BigInteger.prototype.abs = bnAbs;
    BigInteger.prototype.compareTo = bnCompareTo;
    BigInteger.prototype.bitLength = bnBitLength;
    BigInteger.prototype.mod = bnMod;
    BigInteger.prototype.modPowInt = bnModPowInt;
    const ZERO = nbv(0);
    const ONE = nbv(1);
    // jsbn2
    // protected
    BigInteger.prototype.chunkSize = bnpChunkSize;
    BigInteger.prototype.toRadix = bnpToRadix;
    BigInteger.prototype.fromRadix = bnpFromRadix;
    BigInteger.prototype.fromNumber = bnpFromNumber;
    BigInteger.prototype.bitwiseTo = bnpBitwiseTo;
    BigInteger.prototype.changeBit = bnpChangeBit;
    BigInteger.prototype.addTo = bnpAddTo;
    BigInteger.prototype.dMultiply = bnpDMultiply;
    BigInteger.prototype.dAddOffset = bnpDAddOffset;
    BigInteger.prototype.multiplyLowerTo = bnpMultiplyLowerTo;
    BigInteger.prototype.multiplyUpperTo = bnpMultiplyUpperTo;
    BigInteger.prototype.modInt = bnpModInt;
    BigInteger.prototype.millerRabin = bnpMillerRabin;
    // public
    BigInteger.prototype.clone = bnClone;
    BigInteger.prototype.intValue = bnIntValue;
    BigInteger.prototype.byteValue = bnByteValue;
    BigInteger.prototype.shortValue = bnShortValue;
    BigInteger.prototype.signum = bnSigNum;
    BigInteger.prototype.toByteArray = bnToByteArray;
    BigInteger.prototype.equals = bnEquals;
    BigInteger.prototype.min = bnMin;
    BigInteger.prototype.max = bnMax;
    BigInteger.prototype.and = bnAnd;
    BigInteger.prototype.or = bnOr;
    BigInteger.prototype.xor = bnXor;
    BigInteger.prototype.andNot = bnAndNot;
    BigInteger.prototype.not = bnNot;
    BigInteger.prototype.shiftLeft = bnShiftLeft;
    BigInteger.prototype.shiftRight = bnShiftRight;
    BigInteger.prototype.getLowestSetBit = bnGetLowestSetBit;
    BigInteger.prototype.bitCount = bnBitCount;
    BigInteger.prototype.testBit = bnTestBit;
    BigInteger.prototype.setBit = bnSetBit;
    BigInteger.prototype.clearBit = bnClearBit;
    BigInteger.prototype.flipBit = bnFlipBit;
    BigInteger.prototype.add = bnAdd;
    BigInteger.prototype.subtract = bnSubtract;
    BigInteger.prototype.multiply = bnMultiply;
    BigInteger.prototype.divide = bnDivide;
    BigInteger.prototype.remainder = bnRemainder;
    BigInteger.prototype.divideAndRemainder = bnDivideAndRemainder;
    BigInteger.prototype.modPow = bnModPow;
    BigInteger.prototype.modInverse = bnModInverse;
    BigInteger.prototype.pow = bnPow;
    BigInteger.prototype.gcd = bnGCD;
    BigInteger.prototype.isProbablePrime = bnIsProbablePrime;
    // JSBN-specific extension
    BigInteger.prototype.square = bnSquare;

    /*! asn1hex-1.1.js (c) 2012 Kenji Urushima | kjur.github.com/jsrsasign/license
     */
    /**
     * get byte length for ASN.1 L(length) bytes
     * @name getByteLengthOfL_AtObj
     * @memberOf ASN1HEX
     * @function
     * @param {String} s hexadecimal string of ASN.1 DER encoded data
     * @param {Number} pos string index
     * @return byte length for ASN.1 L(length) bytes
     */
    function _asnhex_getByteLengthOfL_AtObj(s, pos) {
        if (s.substring(pos + 2, pos + 3) != '8')
            return 1;
        var i = parseInt(s.substring(pos + 3, pos + 4));
        if (i == 0)
            return -1; // length octet '80' indefinite length
        if (0 < i && i < 10)
            return i + 1; // including '8?' octet;
        return -2; // malformed format
    }
    /**
     * get hexadecimal string for ASN.1 L(length) bytes
     * @name getHexOfL_AtObj
     * @memberOf ASN1HEX
     * @function
     * @param {String} s hexadecimal string of ASN.1 DER encoded data
     * @param {Number} pos string index
     * @return {String} hexadecimal string for ASN.1 L(length) bytes
     */
    function _asnhex_getHexOfL_AtObj(s, pos) {
        var len = _asnhex_getByteLengthOfL_AtObj(s, pos);
        if (len < 1)
            return '';
        return s.substring(pos + 2, pos + 2 + len * 2);
    }
    //
    //   getting ASN.1 length value at the position 'idx' of
    //   hexa decimal string 's'.
    //
    //   f('3082025b02...', 0) ... 82025b ... ???
    //   f('020100', 0) ... 01 ... 1
    //   f('0203001...', 0) ... 03 ... 3
    //   f('02818003...', 0) ... 8180 ... 128
    /**
     * get integer value of ASN.1 length for ASN.1 data
     * @name getIntOfL_AtObj
     * @memberOf ASN1HEX
     * @function
     * @param {String} s hexadecimal string of ASN.1 DER encoded data
     * @param {Number} pos string index
     * @return ASN.1 L(length) integer value
     */
    function _asnhex_getIntOfL_AtObj(s, pos) {
        var hLength = _asnhex_getHexOfL_AtObj(s, pos);
        if (hLength == '')
            return -1;
        var bi;
        if (parseInt(hLength.substring(0, 1)) < 8) {
            bi = parseBigInt(hLength, 16);
        }
        else {
            bi = parseBigInt(hLength.substring(2), 16);
        }
        return bi.intValue();
    }
    /**
     * get ASN.1 value starting string position for ASN.1 object refered by index 'idx'.
     * @name getStartPosOfV_AtObj
     * @memberOf ASN1HEX
     * @function
     * @param {String} s hexadecimal string of ASN.1 DER encoded data
     * @param {Number} pos string index
     */
    function _asnhex_getStartPosOfV_AtObj(s, pos) {
        var l_len = _asnhex_getByteLengthOfL_AtObj(s, pos);
        if (l_len < 0)
            return l_len;
        return pos + (l_len + 1) * 2;
    }
    /**
     * get hexadecimal string of ASN.1 V(value)
     * @name getHexOfV_AtObj
     * @memberOf ASN1HEX
     * @function
     * @param {String} s hexadecimal string of ASN.1 DER encoded data
     * @param {Number} pos string index
     * @return {String} hexadecimal string of ASN.1 value.
     */
    function _asnhex_getHexOfV_AtObj(s, pos) {
        var pos1 = _asnhex_getStartPosOfV_AtObj(s, pos);
        var len = _asnhex_getIntOfL_AtObj(s, pos);
        return s.substring(pos1, pos1 + len * 2);
    }
    /**
     * get next sibling starting index for ASN.1 object string
     * @name getPosOfNextSibling_AtObj
     * @memberOf ASN1HEX
     * @function
     * @param {String} s hexadecimal string of ASN.1 DER encoded data
     * @param {Number} pos string index
     * @return next sibling starting index for ASN.1 object string
     */
    function _asnhex_getPosOfNextSibling_AtObj(s, pos) {
        var pos1 = _asnhex_getStartPosOfV_AtObj(s, pos);
        var len = _asnhex_getIntOfL_AtObj(s, pos);
        return pos1 + len * 2;
    }
    /**
     * get array of indexes of child ASN.1 objects
     * @name getPosArrayOfChildren_AtObj
     * @memberOf ASN1HEX
     * @function
     * @param {String} s hexadecimal string of ASN.1 DER encoded data
     * @param {Number} start string index of ASN.1 object
     * @return {Array of Number} array of indexes for childen of ASN.1 objects
     */
    function _asnhex_getPosArrayOfChildren_AtObj(h, pos) {
        var a = new Array();
        var p0 = _asnhex_getStartPosOfV_AtObj(h, pos);
        a.push(p0);
        var len = _asnhex_getIntOfL_AtObj(h, pos);
        var p = p0;
        var k = 0;
        while (1) {
            var pNext = _asnhex_getPosOfNextSibling_AtObj(h, p);
            if (pNext == null || (pNext - p0 >= (len * 2)))
                break;
            if (k >= 200)
                break;
            a.push(pNext);
            p = pNext;
            k++;
        }
        return a;
    }
    function _rsapem_getPosArrayOfChildrenFromHex(hPrivateKey) {
        var a = new Array();
        var v1 = _asnhex_getStartPosOfV_AtObj(hPrivateKey, 0);
        var n1 = _asnhex_getPosOfNextSibling_AtObj(hPrivateKey, v1);
        var e1 = _asnhex_getPosOfNextSibling_AtObj(hPrivateKey, n1);
        var d1 = _asnhex_getPosOfNextSibling_AtObj(hPrivateKey, e1);
        var p1 = _asnhex_getPosOfNextSibling_AtObj(hPrivateKey, d1);
        var q1 = _asnhex_getPosOfNextSibling_AtObj(hPrivateKey, p1);
        var dp1 = _asnhex_getPosOfNextSibling_AtObj(hPrivateKey, q1);
        var dq1 = _asnhex_getPosOfNextSibling_AtObj(hPrivateKey, dp1);
        var co1 = _asnhex_getPosOfNextSibling_AtObj(hPrivateKey, dq1);
        a.push(v1, n1, e1, d1, p1, q1, dp1, dq1, co1);
        return a;
    }
    function _rsapem_getHexValueArrayOfChildrenFromHex(hPrivateKey) {
        var posArray = _rsapem_getPosArrayOfChildrenFromHex(hPrivateKey);
        var v = _asnhex_getHexOfV_AtObj(hPrivateKey, posArray[0]);
        var n = _asnhex_getHexOfV_AtObj(hPrivateKey, posArray[1]);
        var e = _asnhex_getHexOfV_AtObj(hPrivateKey, posArray[2]);
        var d = _asnhex_getHexOfV_AtObj(hPrivateKey, posArray[3]);
        var p = _asnhex_getHexOfV_AtObj(hPrivateKey, posArray[4]);
        var q = _asnhex_getHexOfV_AtObj(hPrivateKey, posArray[5]);
        var dp = _asnhex_getHexOfV_AtObj(hPrivateKey, posArray[6]);
        var dq = _asnhex_getHexOfV_AtObj(hPrivateKey, posArray[7]);
        var co = _asnhex_getHexOfV_AtObj(hPrivateKey, posArray[8]);
        var a = new Array();
        a.push(v, n, e, d, p, q, dp, dq, co);
        return a;
    }

    // Random number generator - requires a PRNG backend, e.g. prng4.js
    // For best results, put code like
    // <body onClick='rng_seed_time();' onKeyPress='rng_seed_time();'>
    // in your main HTML document.
    function rng_get_bytes(ba) {
        let data = new Uint8Array(ba.length);
        crypto.getRandomValues(data);
        for (let i = 0; i < ba.length; ++i)
            ba[i] = data[i];
    }
    function SecureRandom() { }
    SecureRandom.prototype.nextBytes = rng_get_bytes;

    // @ts-nocheck
    // PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint
    function pkcs1pad2(s, n) {
        if (n < s.length + 11) { // TODO: fix for utf-8
            alert("Message too long for RSA");
            return null;
        }
        var ba = new Array();
        var i = s.length - 1;
        while (i >= 0 && n > 0) {
            var c = s.charCodeAt(i--);
            if (c < 128) { // encode using utf-8
                ba[--n] = c;
            }
            else if ((c > 127) && (c < 2048)) {
                ba[--n] = (c & 63) | 128;
                ba[--n] = (c >> 6) | 192;
            }
            else {
                ba[--n] = (c & 63) | 128;
                ba[--n] = ((c >> 6) & 63) | 128;
                ba[--n] = (c >> 12) | 224;
            }
        }
        ba[--n] = 0;
        var rng = new SecureRandom();
        var x = new Array();
        while (n > 2) { // random non-zero pad
            x[0] = 0;
            while (x[0] == 0)
                rng.nextBytes(x);
            ba[--n] = x[0];
        }
        ba[--n] = 2;
        ba[--n] = 0;
        return new BigInteger(ba);
    }
    // "empty" RSA key constructor
    function RSAKey() {
        this.n = null;
        this.e = 0;
        this.d = null;
        this.p = null;
        this.q = null;
        this.dmp1 = null;
        this.dmq1 = null;
        this.coeff = null;
    }
    // Set the public key fields N and e from hex strings
    function RSASetPublic(N, E) {
        if (N != null && E != null && N.length > 0 && E.length > 0) {
            this.n = parseBigInt(N, 16);
            this.e = parseInt(E, 16);
        }
        else
            alert("Invalid RSA public key");
    }
    // Perform raw public operation on "x": return x^e (mod n)
    function RSADoPublic(x) {
        return x.modPowInt(this.e, this.n);
    }
    function RSADoPrivate(x) {
        if (this.p == null || this.q == null)
            return x.modPow(this.d, this.n);
        // TODO: re-calculate any missing CRT params
        var xp = x.mod(this.p).modPow(this.dmp1, this.p);
        var xq = x.mod(this.q).modPow(this.dmq1, this.q);
        while (xp.compareTo(xq) < 0)
            xp = xp.add(this.p);
        return xp.subtract(xq).multiply(this.coeff).mod(this.p).multiply(this.q).add(xq);
    }
    // Return the PKCS#1 RSA encryption of "text" as an even-length hex string
    function RSAEncrypt(text) {
        var m = pkcs1pad2(text, (this.n.bitLength() + 7) >> 3);
        if (m == null)
            return null;
        var c = this.doPublic(m);
        if (c == null)
            return null;
        var h = c.toString(16);
        if ((h.length & 1) == 0)
            return h;
        else
            return "0" + h;
    }
    // Return the PKCS#1 RSA encryption of "text" as a Base64-encoded string
    //function RSAEncryptB64(text) {
    //  var h = this.encrypt(text);
    //  if(h) return hex2b64(h); else return null;
    //}
    // Binary safe pkcs1 type 2 padding
    function pkcs1pad2hex(hexPlaintext, n) {
        if (n < hexPlaintext.length / 2 + 11) {
            alert("Message too long for RSA");
            return null;
        }
        var ba = new Array();
        var i = hexPlaintext.length;
        while (i >= 2 && n > 0) {
            ba[--n] = parseInt(hexPlaintext.slice(i - 2, i), 16);
            i -= 2;
        }
        ba[--n] = 0;
        var rng = new SecureRandom();
        var x = new Array();
        while (n > 2) { // random non-zero pad
            x[0] = 0;
            while (x[0] == 0)
                rng.nextBytes(x);
            ba[--n] = x[0];
        }
        ba[--n] = 2;
        ba[--n] = 0;
        return new BigInteger(ba);
    }
    //Binary safe pkcs1 type 2 un-padding
    function pkcs1unpad2hex(d, n) {
        var b = d.toByteArray();
        var i = 0;
        while (i < b.length && b[i] == 0)
            ++i;
        if (b.length - i != n - 1 || b[i] != 2)
            return null;
        ++i;
        while (b[i] != 0)
            if (++i >= b.length)
                return null;
        var ret = "";
        while (++i < b.length) {
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
    function RSAtoASN1Hex(include_private) {
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
        function asn(data, type) {
            if (typeof type === 'undefined')
                type = '02';
            // Pad the data with a leading '0' if necessary
            data = (data.length % 2 === 0) ? data : '0' + data;
            // Pad the data again with a '00' to ensure its positive.  Some parser
            // stupid implementations will freak out on negative RSA bits.
            if (parseInt(data.substr(0, 2), 16) > 127)
                data = '00' + data;
            return type + asn_length(data) + data;
        }
        function asn_length(item) {
            var length = item.length / 2; // We're dealing with hex here
            var length_hex = (length.toString(16).length % 2 === 0) ? length.toString(16) : '0' + length.toString(16);
            if (length < 128) {
                return length_hex;
            }
            else {
                var length_length = 128 + length_hex.length / 2;
                var length_length_hex = (length_length.toString(16).length % 2 === 0) ? length_length.toString(16) : '0' + length_length.toString(16);
                return length_length_hex + length_hex;
            }
        }
    }
    function RSAEncryptBinary(hex) {
        var m = pkcs1pad2hex(hex, (this.n.bitLength() + 7) >> 3);
        if (m == null)
            return null;
        var c = this.doPublic(m);
        if (c == null)
            return null;
        var h = c.toString(16);
        if ((h.length & 1) == 0)
            return h;
        else
            return "0" + h;
    }
    function RSADecryptBinary(ctext) {
        var c = parseBigInt(ctext, 16);
        var m = this.doPrivate(c);
        if (m == null)
            return null;
        return pkcs1unpad2hex(m, (this.n.bitLength() + 7) >> 3);
    }
    function RSASetPrivateEx(N, E, D, P, Q, DP, DQ, C) {
        if (N != null && E != null && N.length > 0 && E.length > 0) {
            this.n = parseBigInt(N, 16);
            this.e = parseInt(E, 16);
            this.d = parseBigInt(D, 16);
            this.p = parseBigInt(P, 16);
            this.q = parseBigInt(Q, 16);
            this.dmp1 = parseBigInt(DP, 16);
            this.dmq1 = parseBigInt(DQ, 16);
            this.coeff = parseBigInt(C, 16);
        }
        else
            alert("Invalid RSA private key");
    }
    function RSASetPrivateKeyFromASN1HexString(keyHex) {
        const a = _rsapem_getHexValueArrayOfChildrenFromHex(keyHex);
        this.setPrivateEx(a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
    }
    // protected
    RSAKey.prototype.doPublic = RSADoPublic;
    RSAKey.prototype.doPrivate = RSADoPrivate;
    // public
    RSAKey.prototype.setPublic = RSASetPublic;
    RSAKey.prototype.encrypt = RSAEncrypt;
    //RSAKey.prototype.encrypt_b64 = RSAEncryptB64;
    RSAKey.prototype.encryptBinary = RSAEncryptBinary;
    RSAKey.prototype.decryptBinary = RSADecryptBinary;
    RSAKey.prototype.toASN1HexString = RSAtoASN1Hex;
    RSAKey.prototype.setPrivateEx = RSASetPrivateEx;
    RSAKey.prototype.setPrivateKeyFromASN1HexString = RSASetPrivateKeyFromASN1HexString;

    function getKeeperKeys(fct) {
        let keyNumber = 7;
        return [
            'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM',
            'BKnhy0obglZJK-igwthNLdknoSXRrGB-mvFRzyb_L-DKKefWjYdFD2888qN1ROczz4n3keYSfKz9Koj90Z6w_tQ',
            'BAsPQdCpLIGXdWNLdAwx-3J5lNqUtKbaOMV56hUj8VzxE2USLHuHHuKDeno0ymJt-acxWV1xPlBfNUShhRTR77g',
            'BNYIh_Sv03nRZUUJveE8d2mxKLIDXv654UbshaItHrCJhd6cT7pdZ_XwbdyxAOCWMkBb9AZ4t1XRCsM8-wkEBRg',
            'BA6uNfeYSvqagwu4TOY6wFK4JyU5C200vJna0lH4PJ-SzGVXej8l9dElyQ58_ljfPs5Rq6zVVXpdDe8A7Y3WRhk',
            'BMjTIlXfohI8TDymsHxo0DqYysCy7yZGJ80WhgOBR4QUd6LBDA6-_318a-jCGW96zxXKMm8clDTKpE8w75KG-FY',
            'BJBDU1P1H21IwIdT2brKkPqbQR0Zl0TIHf7Bz_OO9jaNgIwydMkxt4GpBmkYoprZ_DHUGOrno2faB7pmTR7HhuI',
            'BJFF8j-dH7pDEw_U347w2CBM6xYM8Dk5fPPAktjib-opOqzvvbsER-WDHM4ONCSBf9O_obAHzCyygxmtpktDuiE',
            'BDKyWBvLbyZ-jMueORl3JwJnnEpCiZdN7yUvT0vOyjwpPBCDf6zfL4RWzvSkhAAFnwOni_1tQSl8dfXHbXqXsQ8',
            'BDXyZZnrl0tc2jdC5I61JjwkjK2kr7uet9tZjt8StTiJTAQQmnVOYBgbtP08PWDbecxnHghx3kJ8QXq1XE68y8c',
            'BFX68cb97m9_sweGdOVavFM3j5ot6gveg6xT4BtGahfGhKib-zdZyO9pwvv1cBda9ahkSzo1BQ4NVXp9qRyqVGU'
        ].reduce((keys, key) => {
            keys[keyNumber++] = fct(key);
            return keys;
        }, []);
    }

    function webSafe64(source) {
        return source.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
    function webSafe64FromBytes(source) {
        return webSafe64(platform.bytesToBase64(source));
    }
    function normal64(source) {
        return source.replace(/-/g, '+').replace(/_/g, '/') + '=='.substring(0, (3 * source.length) % 4);
    }
    function normal64Bytes(source) {
        return platform.base64ToBytes(normal64(source));
    }

    var CloseReasonCode;
    (function (CloseReasonCode) {
        CloseReasonCode[CloseReasonCode["CANNOT_ACCEPT"] = 1003] = "CANNOT_ACCEPT";
        CloseReasonCode[CloseReasonCode["NOT_CONSISTENT"] = 1007] = "NOT_CONSISTENT";
        CloseReasonCode[CloseReasonCode["VIOLATED_POLICY"] = 1008] = "VIOLATED_POLICY";
        CloseReasonCode[CloseReasonCode["TRY_AGAIN_LATER"] = 1013] = "TRY_AGAIN_LATER";
    })(CloseReasonCode || (CloseReasonCode = {}));
    function socketSendMessage(message, socket, createdSocket) {
        switch (socket.readyState) {
            case 0: // CONNECTING
                if (createdSocket.messageQueue.indexOf(message) === -1)
                    createdSocket.messageQueue.push(message);
                break;
            case 1: // OPEN
                if (createdSocket.messageQueue.indexOf(message) === -1)
                    createdSocket.messageQueue.push(message);
                if (createdSocket.messageQueue.length > 0) {
                    for (let counter = 0; counter < createdSocket.messageQueue.length; counter++) {
                        socket.send(createdSocket.messageQueue[counter]);
                    }
                }
                createdSocket.messageQueue.length = 0;
                break;
            case 2: // CLOSING
            case 3: // CLOSED
                createdSocket.messageQueue.length = 0;
                console.error('Trying to send a message while in the CLOSING or CLOSED state');
                break;
        }
    }

    function string_to_bytes(str, utf8 = false) {
        var len = str.length, bytes = new Uint8Array(utf8 ? 4 * len : len);
        for (var i = 0, j = 0; i < len; i++) {
            var c = str.charCodeAt(i);
            if (utf8 && 0xd800 <= c && c <= 0xdbff) {
                if (++i >= len)
                    throw new Error('Malformed string, low surrogate expected at position ' + i);
                c = ((c ^ 0xd800) << 10) | 0x10000 | (str.charCodeAt(i) ^ 0xdc00);
            }
            else if (!utf8 && c >>> 8) {
                throw new Error('Wide characters are not allowed.');
            }
            if (!utf8 || c <= 0x7f) {
                bytes[j++] = c;
            }
            else if (c <= 0x7ff) {
                bytes[j++] = 0xc0 | (c >> 6);
                bytes[j++] = 0x80 | (c & 0x3f);
            }
            else if (c <= 0xffff) {
                bytes[j++] = 0xe0 | (c >> 12);
                bytes[j++] = 0x80 | ((c >> 6) & 0x3f);
                bytes[j++] = 0x80 | (c & 0x3f);
            }
            else {
                bytes[j++] = 0xf0 | (c >> 18);
                bytes[j++] = 0x80 | ((c >> 12) & 0x3f);
                bytes[j++] = 0x80 | ((c >> 6) & 0x3f);
                bytes[j++] = 0x80 | (c & 0x3f);
            }
        }
        return bytes.subarray(0, j);
    }
    function is_bytes(a) {
        return a instanceof Uint8Array;
    }
    function _heap_init(heap, heapSize) {
        const size = heap ? heap.byteLength : heapSize || 65536;
        if (size & 0xfff || size <= 0)
            throw new Error('heap size must be a positive integer and a multiple of 4096');
        heap = heap || new Uint8Array(new ArrayBuffer(size));
        return heap;
    }
    function _heap_write(heap, hpos, data, dpos, dlen) {
        const hlen = heap.length - hpos;
        const wlen = hlen < dlen ? hlen : dlen;
        heap.set(data.subarray(dpos, dpos + wlen), hpos);
        return wlen;
    }
    function joinBytes(...arg) {
        const totalLenght = arg.reduce((sum, curr) => sum + curr.length, 0);
        const ret = new Uint8Array(totalLenght);
        let cursor = 0;
        for (let i = 0; i < arg.length; i++) {
            ret.set(arg[i], cursor);
            cursor += arg[i].length;
        }
        return ret;
    }
    class IllegalArgumentError extends Error {
        constructor(...args) {
            super(...args);
        }
    }
    class SecurityError extends Error {
        constructor(...args) {
            super(...args);
        }
    }

    /**
     * @file {@link http://asmjs.org Asm.js} implementation of the {@link https://en.wikipedia.org/wiki/Advanced_Encryption_Standard Advanced Encryption Standard}.
     * @author Artem S Vybornov <vybornov@gmail.com>
     * @license MIT
     */
    var AES_asm = function () {

      /**
       * Galois Field stuff init flag
       */
      var ginit_done = false;

      /**
       * Galois Field exponentiation and logarithm tables for 3 (the generator)
       */
      var gexp3, glog3;

      /**
       * Init Galois Field tables
       */
      function ginit() {
        gexp3 = [],
          glog3 = [];

        var a = 1, c, d;
        for (c = 0; c < 255; c++) {
          gexp3[c] = a;

          // Multiply by three
          d = a & 0x80, a <<= 1, a &= 255;
          if (d === 0x80) a ^= 0x1b;
          a ^= gexp3[c];

          // Set the log table value
          glog3[gexp3[c]] = c;
        }
        gexp3[255] = gexp3[0];
        glog3[0] = 0;

        ginit_done = true;
      }

      /**
       * Galois Field multiplication
       * @param {number} a
       * @param {number} b
       * @return {number}
       */
      function gmul(a, b) {
        var c = gexp3[(glog3[a] + glog3[b]) % 255];
        if (a === 0 || b === 0) c = 0;
        return c;
      }

      /**
       * Galois Field reciprocal
       * @param {number} a
       * @return {number}
       */
      function ginv(a) {
        var i = gexp3[255 - glog3[a]];
        if (a === 0) i = 0;
        return i;
      }

      /**
       * AES stuff init flag
       */
      var aes_init_done = false;

      /**
       * Encryption, Decryption, S-Box and KeyTransform tables
       *
       * @type {number[]}
       */
      var aes_sbox;

      /**
       * @type {number[]}
       */
      var aes_sinv;

      /**
       * @type {number[][]}
       */
      var aes_enc;

      /**
       * @type {number[][]}
       */
      var aes_dec;

      /**
       * Init AES tables
       */
      function aes_init() {
        if (!ginit_done) ginit();

        // Calculates AES S-Box value
        function _s(a) {
          var c, s, x;
          s = x = ginv(a);
          for (c = 0; c < 4; c++) {
            s = ((s << 1) | (s >>> 7)) & 255;
            x ^= s;
          }
          x ^= 99;
          return x;
        }

        // Tables
        aes_sbox = [],
          aes_sinv = [],
          aes_enc = [[], [], [], []],
          aes_dec = [[], [], [], []];

        for (var i = 0; i < 256; i++) {
          var s = _s(i);

          // S-Box and its inverse
          aes_sbox[i] = s;
          aes_sinv[s] = i;

          // Ecryption and Decryption tables
          aes_enc[0][i] = (gmul(2, s) << 24) | (s << 16) | (s << 8) | gmul(3, s);
          aes_dec[0][s] = (gmul(14, i) << 24) | (gmul(9, i) << 16) | (gmul(13, i) << 8) | gmul(11, i);
          // Rotate tables
          for (var t = 1; t < 4; t++) {
            aes_enc[t][i] = (aes_enc[t - 1][i] >>> 8) | (aes_enc[t - 1][i] << 24);
            aes_dec[t][s] = (aes_dec[t - 1][s] >>> 8) | (aes_dec[t - 1][s] << 24);
          }
        }

        aes_init_done = true;
      }

      /**
       * Asm.js module constructor.
       *
       * <p>
       * Heap buffer layout by offset:
       * <pre>
       * 0x0000   encryption key schedule
       * 0x0400   decryption key schedule
       * 0x0800   sbox
       * 0x0c00   inv sbox
       * 0x1000   encryption tables
       * 0x2000   decryption tables
       * 0x3000   reserved (future GCM multiplication lookup table)
       * 0x4000   data
       * </pre>
       * Don't touch anything before <code>0x400</code>.
       * </p>
       *
       * @alias AES_asm
       * @class
       * @param foreign - <i>ignored</i>
       * @param buffer - heap buffer to link with
       */
      var wrapper = function (foreign, buffer) {
        // Init AES stuff for the first time
        if (!aes_init_done) aes_init();

        // Fill up AES tables
        var heap = new Uint32Array(buffer);
        heap.set(aes_sbox, 0x0800 >> 2);
        heap.set(aes_sinv, 0x0c00 >> 2);
        for (var i = 0; i < 4; i++) {
          heap.set(aes_enc[i], (0x1000 + 0x400 * i) >> 2);
          heap.set(aes_dec[i], (0x2000 + 0x400 * i) >> 2);
        }

        /**
         * Calculate AES key schedules.
         * @instance
         * @memberof AES_asm
         * @param {number} ks - key size, 4/6/8 (for 128/192/256-bit key correspondingly)
         * @param {number} k0 - key vector components
         * @param {number} k1 - key vector components
         * @param {number} k2 - key vector components
         * @param {number} k3 - key vector components
         * @param {number} k4 - key vector components
         * @param {number} k5 - key vector components
         * @param {number} k6 - key vector components
         * @param {number} k7 - key vector components
         */
        function set_key(ks, k0, k1, k2, k3, k4, k5, k6, k7) {
          var ekeys = heap.subarray(0x000, 60),
            dkeys = heap.subarray(0x100, 0x100 + 60);

          // Encryption key schedule
          ekeys.set([k0, k1, k2, k3, k4, k5, k6, k7]);
          for (var i = ks, rcon = 1; i < 4 * ks + 28; i++) {
            var k = ekeys[i - 1];
            if ((i % ks === 0) || (ks === 8 && i % ks === 4)) {
              k = aes_sbox[k >>> 24] << 24 ^ aes_sbox[k >>> 16 & 255] << 16 ^ aes_sbox[k >>> 8 & 255] << 8 ^ aes_sbox[k & 255];
            }
            if (i % ks === 0) {
              k = (k << 8) ^ (k >>> 24) ^ (rcon << 24);
              rcon = (rcon << 1) ^ ((rcon & 0x80) ? 0x1b : 0);
            }
            ekeys[i] = ekeys[i - ks] ^ k;
          }

          // Decryption key schedule
          for (var j = 0; j < i; j += 4) {
            for (var jj = 0; jj < 4; jj++) {
              var k = ekeys[i - (4 + j) + (4 - jj) % 4];
              if (j < 4 || j >= i - 4) {
                dkeys[j + jj] = k;
              } else {
                dkeys[j + jj] = aes_dec[0][aes_sbox[k >>> 24]]
                  ^ aes_dec[1][aes_sbox[k >>> 16 & 255]]
                  ^ aes_dec[2][aes_sbox[k >>> 8 & 255]]
                  ^ aes_dec[3][aes_sbox[k & 255]];
              }
            }
          }

          // Set rounds number
          asm.set_rounds(ks + 5);
        }

        // create library object with necessary properties
        var stdlib = {Uint8Array: Uint8Array, Uint32Array: Uint32Array};

        var asm = function (stdlib, foreign, buffer) {
          "use asm";

          var S0 = 0, S1 = 0, S2 = 0, S3 = 0,
            I0 = 0, I1 = 0, I2 = 0, I3 = 0,
            N0 = 0, N1 = 0, N2 = 0, N3 = 0,
            M0 = 0, M1 = 0, M2 = 0, M3 = 0,
            H0 = 0, H1 = 0, H2 = 0, H3 = 0,
            R = 0;

          var HEAP = new stdlib.Uint32Array(buffer),
            DATA = new stdlib.Uint8Array(buffer);

          /**
           * AES core
           * @param {number} k - precomputed key schedule offset
           * @param {number} s - precomputed sbox table offset
           * @param {number} t - precomputed round table offset
           * @param {number} r - number of inner rounds to perform
           * @param {number} x0 - 128-bit input block vector
           * @param {number} x1 - 128-bit input block vector
           * @param {number} x2 - 128-bit input block vector
           * @param {number} x3 - 128-bit input block vector
           */
          function _core(k, s, t, r, x0, x1, x2, x3) {
            k = k | 0;
            s = s | 0;
            t = t | 0;
            r = r | 0;
            x0 = x0 | 0;
            x1 = x1 | 0;
            x2 = x2 | 0;
            x3 = x3 | 0;

            var t1 = 0, t2 = 0, t3 = 0,
              y0 = 0, y1 = 0, y2 = 0, y3 = 0,
              i = 0;

            t1 = t | 0x400, t2 = t | 0x800, t3 = t | 0xc00;

            // round 0
            x0 = x0 ^ HEAP[(k | 0) >> 2],
              x1 = x1 ^ HEAP[(k | 4) >> 2],
              x2 = x2 ^ HEAP[(k | 8) >> 2],
              x3 = x3 ^ HEAP[(k | 12) >> 2];

            // round 1..r
            for (i = 16; (i | 0) <= (r << 4); i = (i + 16) | 0) {
              y0 = HEAP[(t | x0 >> 22 & 1020) >> 2] ^ HEAP[(t1 | x1 >> 14 & 1020) >> 2] ^ HEAP[(t2 | x2 >> 6 & 1020) >> 2] ^ HEAP[(t3 | x3 << 2 & 1020) >> 2] ^ HEAP[(k | i | 0) >> 2],
                y1 = HEAP[(t | x1 >> 22 & 1020) >> 2] ^ HEAP[(t1 | x2 >> 14 & 1020) >> 2] ^ HEAP[(t2 | x3 >> 6 & 1020) >> 2] ^ HEAP[(t3 | x0 << 2 & 1020) >> 2] ^ HEAP[(k | i | 4) >> 2],
                y2 = HEAP[(t | x2 >> 22 & 1020) >> 2] ^ HEAP[(t1 | x3 >> 14 & 1020) >> 2] ^ HEAP[(t2 | x0 >> 6 & 1020) >> 2] ^ HEAP[(t3 | x1 << 2 & 1020) >> 2] ^ HEAP[(k | i | 8) >> 2],
                y3 = HEAP[(t | x3 >> 22 & 1020) >> 2] ^ HEAP[(t1 | x0 >> 14 & 1020) >> 2] ^ HEAP[(t2 | x1 >> 6 & 1020) >> 2] ^ HEAP[(t3 | x2 << 2 & 1020) >> 2] ^ HEAP[(k | i | 12) >> 2];
              x0 = y0, x1 = y1, x2 = y2, x3 = y3;
            }

            // final round
            S0 = HEAP[(s | x0 >> 22 & 1020) >> 2] << 24 ^ HEAP[(s | x1 >> 14 & 1020) >> 2] << 16 ^ HEAP[(s | x2 >> 6 & 1020) >> 2] << 8 ^ HEAP[(s | x3 << 2 & 1020) >> 2] ^ HEAP[(k | i | 0) >> 2],
              S1 = HEAP[(s | x1 >> 22 & 1020) >> 2] << 24 ^ HEAP[(s | x2 >> 14 & 1020) >> 2] << 16 ^ HEAP[(s | x3 >> 6 & 1020) >> 2] << 8 ^ HEAP[(s | x0 << 2 & 1020) >> 2] ^ HEAP[(k | i | 4) >> 2],
              S2 = HEAP[(s | x2 >> 22 & 1020) >> 2] << 24 ^ HEAP[(s | x3 >> 14 & 1020) >> 2] << 16 ^ HEAP[(s | x0 >> 6 & 1020) >> 2] << 8 ^ HEAP[(s | x1 << 2 & 1020) >> 2] ^ HEAP[(k | i | 8) >> 2],
              S3 = HEAP[(s | x3 >> 22 & 1020) >> 2] << 24 ^ HEAP[(s | x0 >> 14 & 1020) >> 2] << 16 ^ HEAP[(s | x1 >> 6 & 1020) >> 2] << 8 ^ HEAP[(s | x2 << 2 & 1020) >> 2] ^ HEAP[(k | i | 12) >> 2];
          }

          /**
           * ECB mode encryption
           * @param {number} x0 - 128-bit input block vector
           * @param {number} x1 - 128-bit input block vector
           * @param {number} x2 - 128-bit input block vector
           * @param {number} x3 - 128-bit input block vector
           */
          function _ecb_enc(x0, x1, x2, x3) {
            x0 = x0 | 0;
            x1 = x1 | 0;
            x2 = x2 | 0;
            x3 = x3 | 0;

            _core(
              0x0000, 0x0800, 0x1000,
              R,
              x0,
              x1,
              x2,
              x3
            );
          }

          /**
           * ECB mode decryption
           * @param {number} x0 - 128-bit input block vector
           * @param {number} x1 - 128-bit input block vector
           * @param {number} x2 - 128-bit input block vector
           * @param {number} x3 - 128-bit input block vector
           */
          function _ecb_dec(x0, x1, x2, x3) {
            x0 = x0 | 0;
            x1 = x1 | 0;
            x2 = x2 | 0;
            x3 = x3 | 0;

            var t = 0;

            _core(
              0x0400, 0x0c00, 0x2000,
              R,
              x0,
              x3,
              x2,
              x1
            );

            t = S1, S1 = S3, S3 = t;
          }


          /**
           * CBC mode encryption
           * @param {number} x0 - 128-bit input block vector
           * @param {number} x1 - 128-bit input block vector
           * @param {number} x2 - 128-bit input block vector
           * @param {number} x3 - 128-bit input block vector
           */
          function _cbc_enc(x0, x1, x2, x3) {
            x0 = x0 | 0;
            x1 = x1 | 0;
            x2 = x2 | 0;
            x3 = x3 | 0;

            _core(
              0x0000, 0x0800, 0x1000,
              R,
              I0 ^ x0,
              I1 ^ x1,
              I2 ^ x2,
              I3 ^ x3
            );

            I0 = S0,
              I1 = S1,
              I2 = S2,
              I3 = S3;
          }

          /**
           * CBC mode decryption
           * @param {number} x0 - 128-bit input block vector
           * @param {number} x1 - 128-bit input block vector
           * @param {number} x2 - 128-bit input block vector
           * @param {number} x3 - 128-bit input block vector
           */
          function _cbc_dec(x0, x1, x2, x3) {
            x0 = x0 | 0;
            x1 = x1 | 0;
            x2 = x2 | 0;
            x3 = x3 | 0;

            var t = 0;

            _core(
              0x0400, 0x0c00, 0x2000,
              R,
              x0,
              x3,
              x2,
              x1
            );

            t = S1, S1 = S3, S3 = t;

            S0 = S0 ^ I0,
              S1 = S1 ^ I1,
              S2 = S2 ^ I2,
              S3 = S3 ^ I3;

            I0 = x0,
              I1 = x1,
              I2 = x2,
              I3 = x3;
          }

          /**
           * CFB mode encryption
           * @param {number} x0 - 128-bit input block vector
           * @param {number} x1 - 128-bit input block vector
           * @param {number} x2 - 128-bit input block vector
           * @param {number} x3 - 128-bit input block vector
           */
          function _cfb_enc(x0, x1, x2, x3) {
            x0 = x0 | 0;
            x1 = x1 | 0;
            x2 = x2 | 0;
            x3 = x3 | 0;

            _core(
              0x0000, 0x0800, 0x1000,
              R,
              I0,
              I1,
              I2,
              I3
            );

            I0 = S0 = S0 ^ x0,
              I1 = S1 = S1 ^ x1,
              I2 = S2 = S2 ^ x2,
              I3 = S3 = S3 ^ x3;
          }


          /**
           * CFB mode decryption
           * @param {number} x0 - 128-bit input block vector
           * @param {number} x1 - 128-bit input block vector
           * @param {number} x2 - 128-bit input block vector
           * @param {number} x3 - 128-bit input block vector
           */
          function _cfb_dec(x0, x1, x2, x3) {
            x0 = x0 | 0;
            x1 = x1 | 0;
            x2 = x2 | 0;
            x3 = x3 | 0;

            _core(
              0x0000, 0x0800, 0x1000,
              R,
              I0,
              I1,
              I2,
              I3
            );

            S0 = S0 ^ x0,
              S1 = S1 ^ x1,
              S2 = S2 ^ x2,
              S3 = S3 ^ x3;

            I0 = x0,
              I1 = x1,
              I2 = x2,
              I3 = x3;
          }

          /**
           * OFB mode encryption / decryption
           * @param {number} x0 - 128-bit input block vector
           * @param {number} x1 - 128-bit input block vector
           * @param {number} x2 - 128-bit input block vector
           * @param {number} x3 - 128-bit input block vector
           */
          function _ofb(x0, x1, x2, x3) {
            x0 = x0 | 0;
            x1 = x1 | 0;
            x2 = x2 | 0;
            x3 = x3 | 0;

            _core(
              0x0000, 0x0800, 0x1000,
              R,
              I0,
              I1,
              I2,
              I3
            );

            I0 = S0,
              I1 = S1,
              I2 = S2,
              I3 = S3;

            S0 = S0 ^ x0,
              S1 = S1 ^ x1,
              S2 = S2 ^ x2,
              S3 = S3 ^ x3;
          }

          /**
           * CTR mode encryption / decryption
           * @param {number} x0 - 128-bit input block vector
           * @param {number} x1 - 128-bit input block vector
           * @param {number} x2 - 128-bit input block vector
           * @param {number} x3 - 128-bit input block vector
           */
          function _ctr(x0, x1, x2, x3) {
            x0 = x0 | 0;
            x1 = x1 | 0;
            x2 = x2 | 0;
            x3 = x3 | 0;

            _core(
              0x0000, 0x0800, 0x1000,
              R,
              N0,
              N1,
              N2,
              N3
            );

            N3 = (~M3 & N3) | M3 & (N3 + 1);
              N2 = (~M2 & N2) | M2 & (N2 + ((N3 | 0) == 0));
              N1 = (~M1 & N1) | M1 & (N1 + ((N2 | 0) == 0));
              N0 = (~M0 & N0) | M0 & (N0 + ((N1 | 0) == 0));

            S0 = S0 ^ x0;
              S1 = S1 ^ x1;
              S2 = S2 ^ x2;
              S3 = S3 ^ x3;
          }

          /**
           * GCM mode MAC calculation
           * @param {number} x0 - 128-bit input block vector
           * @param {number} x1 - 128-bit input block vector
           * @param {number} x2 - 128-bit input block vector
           * @param {number} x3 - 128-bit input block vector
           */
          function _gcm_mac(x0, x1, x2, x3) {
            x0 = x0 | 0;
            x1 = x1 | 0;
            x2 = x2 | 0;
            x3 = x3 | 0;

            var y0 = 0, y1 = 0, y2 = 0, y3 = 0,
              z0 = 0, z1 = 0, z2 = 0, z3 = 0,
              i = 0, c = 0;

            x0 = x0 ^ I0,
              x1 = x1 ^ I1,
              x2 = x2 ^ I2,
              x3 = x3 ^ I3;

            y0 = H0 | 0,
              y1 = H1 | 0,
              y2 = H2 | 0,
              y3 = H3 | 0;

            for (; (i | 0) < 128; i = (i + 1) | 0) {
              if (y0 >>> 31) {
                z0 = z0 ^ x0,
                  z1 = z1 ^ x1,
                  z2 = z2 ^ x2,
                  z3 = z3 ^ x3;
              }

              y0 = (y0 << 1) | (y1 >>> 31),
                y1 = (y1 << 1) | (y2 >>> 31),
                y2 = (y2 << 1) | (y3 >>> 31),
                y3 = (y3 << 1);

              c = x3 & 1;

              x3 = (x3 >>> 1) | (x2 << 31),
                x2 = (x2 >>> 1) | (x1 << 31),
                x1 = (x1 >>> 1) | (x0 << 31),
                x0 = (x0 >>> 1);

              if (c) x0 = x0 ^ 0xe1000000;
            }

            I0 = z0,
              I1 = z1,
              I2 = z2,
              I3 = z3;
          }

          /**
           * Set the internal rounds number.
           * @instance
           * @memberof AES_asm
           * @param {number} r - number if inner AES rounds
           */
          function set_rounds(r) {
            r = r | 0;
            R = r;
          }

          /**
           * Populate the internal state of the module.
           * @instance
           * @memberof AES_asm
           * @param {number} s0 - state vector
           * @param {number} s1 - state vector
           * @param {number} s2 - state vector
           * @param {number} s3 - state vector
           */
          function set_state(s0, s1, s2, s3) {
            s0 = s0 | 0;
            s1 = s1 | 0;
            s2 = s2 | 0;
            s3 = s3 | 0;

            S0 = s0,
              S1 = s1,
              S2 = s2,
              S3 = s3;
          }

          /**
           * Populate the internal iv of the module.
           * @instance
           * @memberof AES_asm
           * @param {number} i0 - iv vector
           * @param {number} i1 - iv vector
           * @param {number} i2 - iv vector
           * @param {number} i3 - iv vector
           */
          function set_iv(i0, i1, i2, i3) {
            i0 = i0 | 0;
            i1 = i1 | 0;
            i2 = i2 | 0;
            i3 = i3 | 0;

            I0 = i0,
              I1 = i1,
              I2 = i2,
              I3 = i3;
          }

          /**
           * Set nonce for CTR-family modes.
           * @instance
           * @memberof AES_asm
           * @param {number} n0 - nonce vector
           * @param {number} n1 - nonce vector
           * @param {number} n2 - nonce vector
           * @param {number} n3 - nonce vector
           */
          function set_nonce(n0, n1, n2, n3) {
            n0 = n0 | 0;
            n1 = n1 | 0;
            n2 = n2 | 0;
            n3 = n3 | 0;

            N0 = n0,
              N1 = n1,
              N2 = n2,
              N3 = n3;
          }

          /**
           * Set counter mask for CTR-family modes.
           * @instance
           * @memberof AES_asm
           * @param {number} m0 - counter mask vector
           * @param {number} m1 - counter mask vector
           * @param {number} m2 - counter mask vector
           * @param {number} m3 - counter mask vector
           */
          function set_mask(m0, m1, m2, m3) {
            m0 = m0 | 0;
            m1 = m1 | 0;
            m2 = m2 | 0;
            m3 = m3 | 0;

            M0 = m0,
              M1 = m1,
              M2 = m2,
              M3 = m3;
          }

          /**
           * Set counter for CTR-family modes.
           * @instance
           * @memberof AES_asm
           * @param {number} c0 - counter vector
           * @param {number} c1 - counter vector
           * @param {number} c2 - counter vector
           * @param {number} c3 - counter vector
           */
          function set_counter(c0, c1, c2, c3) {
            c0 = c0 | 0;
            c1 = c1 | 0;
            c2 = c2 | 0;
            c3 = c3 | 0;

            N3 = (~M3 & N3) | M3 & c3,
              N2 = (~M2 & N2) | M2 & c2,
              N1 = (~M1 & N1) | M1 & c1,
              N0 = (~M0 & N0) | M0 & c0;
          }

          /**
           * Store the internal state vector into the heap.
           * @instance
           * @memberof AES_asm
           * @param {number} pos - offset where to put the data
           * @return {number} The number of bytes have been written into the heap, always 16.
           */
          function get_state(pos) {
            pos = pos | 0;

            if (pos & 15) return -1;

            DATA[pos | 0] = S0 >>> 24,
              DATA[pos | 1] = S0 >>> 16 & 255,
              DATA[pos | 2] = S0 >>> 8 & 255,
              DATA[pos | 3] = S0 & 255,
              DATA[pos | 4] = S1 >>> 24,
              DATA[pos | 5] = S1 >>> 16 & 255,
              DATA[pos | 6] = S1 >>> 8 & 255,
              DATA[pos | 7] = S1 & 255,
              DATA[pos | 8] = S2 >>> 24,
              DATA[pos | 9] = S2 >>> 16 & 255,
              DATA[pos | 10] = S2 >>> 8 & 255,
              DATA[pos | 11] = S2 & 255,
              DATA[pos | 12] = S3 >>> 24,
              DATA[pos | 13] = S3 >>> 16 & 255,
              DATA[pos | 14] = S3 >>> 8 & 255,
              DATA[pos | 15] = S3 & 255;

            return 16;
          }

          /**
           * Store the internal iv vector into the heap.
           * @instance
           * @memberof AES_asm
           * @param {number} pos - offset where to put the data
           * @return {number} The number of bytes have been written into the heap, always 16.
           */
          function get_iv(pos) {
            pos = pos | 0;

            if (pos & 15) return -1;

            DATA[pos | 0] = I0 >>> 24,
              DATA[pos | 1] = I0 >>> 16 & 255,
              DATA[pos | 2] = I0 >>> 8 & 255,
              DATA[pos | 3] = I0 & 255,
              DATA[pos | 4] = I1 >>> 24,
              DATA[pos | 5] = I1 >>> 16 & 255,
              DATA[pos | 6] = I1 >>> 8 & 255,
              DATA[pos | 7] = I1 & 255,
              DATA[pos | 8] = I2 >>> 24,
              DATA[pos | 9] = I2 >>> 16 & 255,
              DATA[pos | 10] = I2 >>> 8 & 255,
              DATA[pos | 11] = I2 & 255,
              DATA[pos | 12] = I3 >>> 24,
              DATA[pos | 13] = I3 >>> 16 & 255,
              DATA[pos | 14] = I3 >>> 8 & 255,
              DATA[pos | 15] = I3 & 255;

            return 16;
          }

          /**
           * GCM initialization.
           * @instance
           * @memberof AES_asm
           */
          function gcm_init() {
            _ecb_enc(0, 0, 0, 0);
            H0 = S0,
              H1 = S1,
              H2 = S2,
              H3 = S3;
          }

          /**
           * Perform ciphering operation on the supplied data.
           * @instance
           * @memberof AES_asm
           * @param {number} mode - block cipher mode (see {@link AES_asm} mode constants)
           * @param {number} pos - offset of the data being processed
           * @param {number} len - length of the data being processed
           * @return {number} Actual amount of data have been processed.
           */
          function cipher(mode, pos, len) {
            mode = mode | 0;
            pos = pos | 0;
            len = len | 0;

            var ret = 0;

            if (pos & 15) return -1;

            while ((len | 0) >= 16) {
              _cipher_modes[mode & 7](
                DATA[pos | 0] << 24 | DATA[pos | 1] << 16 | DATA[pos | 2] << 8 | DATA[pos | 3],
                DATA[pos | 4] << 24 | DATA[pos | 5] << 16 | DATA[pos | 6] << 8 | DATA[pos | 7],
                DATA[pos | 8] << 24 | DATA[pos | 9] << 16 | DATA[pos | 10] << 8 | DATA[pos | 11],
                DATA[pos | 12] << 24 | DATA[pos | 13] << 16 | DATA[pos | 14] << 8 | DATA[pos | 15]
              );

              DATA[pos | 0] = S0 >>> 24,
                DATA[pos | 1] = S0 >>> 16 & 255,
                DATA[pos | 2] = S0 >>> 8 & 255,
                DATA[pos | 3] = S0 & 255,
                DATA[pos | 4] = S1 >>> 24,
                DATA[pos | 5] = S1 >>> 16 & 255,
                DATA[pos | 6] = S1 >>> 8 & 255,
                DATA[pos | 7] = S1 & 255,
                DATA[pos | 8] = S2 >>> 24,
                DATA[pos | 9] = S2 >>> 16 & 255,
                DATA[pos | 10] = S2 >>> 8 & 255,
                DATA[pos | 11] = S2 & 255,
                DATA[pos | 12] = S3 >>> 24,
                DATA[pos | 13] = S3 >>> 16 & 255,
                DATA[pos | 14] = S3 >>> 8 & 255,
                DATA[pos | 15] = S3 & 255;

              ret = (ret + 16) | 0,
                pos = (pos + 16) | 0,
                len = (len - 16) | 0;
            }

            return ret | 0;
          }

          /**
           * Calculates MAC of the supplied data.
           * @instance
           * @memberof AES_asm
           * @param {number} mode - block cipher mode (see {@link AES_asm} mode constants)
           * @param {number} pos - offset of the data being processed
           * @param {number} len - length of the data being processed
           * @return {number} Actual amount of data have been processed.
           */
          function mac(mode, pos, len) {
            mode = mode | 0;
            pos = pos | 0;
            len = len | 0;

            var ret = 0;

            if (pos & 15) return -1;

            while ((len | 0) >= 16) {
              _mac_modes[mode & 1](
                DATA[pos | 0] << 24 | DATA[pos | 1] << 16 | DATA[pos | 2] << 8 | DATA[pos | 3],
                DATA[pos | 4] << 24 | DATA[pos | 5] << 16 | DATA[pos | 6] << 8 | DATA[pos | 7],
                DATA[pos | 8] << 24 | DATA[pos | 9] << 16 | DATA[pos | 10] << 8 | DATA[pos | 11],
                DATA[pos | 12] << 24 | DATA[pos | 13] << 16 | DATA[pos | 14] << 8 | DATA[pos | 15]
              );

              ret = (ret + 16) | 0,
                pos = (pos + 16) | 0,
                len = (len - 16) | 0;
            }

            return ret | 0;
          }

          /**
           * AES cipher modes table (virual methods)
           */
          var _cipher_modes = [_ecb_enc, _ecb_dec, _cbc_enc, _cbc_dec, _cfb_enc, _cfb_dec, _ofb, _ctr];

          /**
           * AES MAC modes table (virual methods)
           */
          var _mac_modes = [_cbc_enc, _gcm_mac];

          /**
           * Asm.js module exports
           */
          return {
            set_rounds: set_rounds,
            set_state: set_state,
            set_iv: set_iv,
            set_nonce: set_nonce,
            set_mask: set_mask,
            set_counter: set_counter,
            get_state: get_state,
            get_iv: get_iv,
            gcm_init: gcm_init,
            cipher: cipher,
            mac: mac,
          };
        }(stdlib, foreign, buffer);

        asm.set_key = set_key;

        return asm;
      };

      /**
       * AES enciphering mode constants
       * @enum {number}
       * @const
       */
      wrapper.ENC = {
        ECB: 0,
        CBC: 2,
        CFB: 4,
        OFB: 6,
        CTR: 7,
      },

        /**
         * AES deciphering mode constants
         * @enum {number}
         * @const
         */
        wrapper.DEC = {
          ECB: 1,
          CBC: 3,
          CFB: 5,
          OFB: 6,
          CTR: 7,
        },

        /**
         * AES MAC mode constants
         * @enum {number}
         * @const
         */
        wrapper.MAC = {
          CBC: 0,
          GCM: 1,
        };

      /**
       * Heap data offset
       * @type {number}
       * @const
       */
      wrapper.HEAP_DATA = 0x4000;

      return wrapper;
    }();

    class AES {
        constructor(key, iv, padding = true, mode) {
            this.pos = 0;
            this.len = 0;
            this.mode = mode;
            // The AES "worker"
            this.heap = _heap_init().subarray(AES_asm.HEAP_DATA);
            this.asm = new AES_asm(null, this.heap.buffer);
            // The AES object state
            this.pos = 0;
            this.len = 0;
            // Key
            const keylen = key.length;
            if (keylen !== 16 && keylen !== 24 && keylen !== 32)
                throw new IllegalArgumentError('illegal key size');
            const keyview = new DataView(key.buffer, key.byteOffset, key.byteLength);
            this.asm.set_key(keylen >> 2, keyview.getUint32(0), keyview.getUint32(4), keyview.getUint32(8), keyview.getUint32(12), keylen > 16 ? keyview.getUint32(16) : 0, keylen > 16 ? keyview.getUint32(20) : 0, keylen > 24 ? keyview.getUint32(24) : 0, keylen > 24 ? keyview.getUint32(28) : 0);
            // IV
            if (iv !== undefined) {
                if (iv.length !== 16)
                    throw new IllegalArgumentError('illegal iv size');
                let ivview = new DataView(iv.buffer, iv.byteOffset, iv.byteLength);
                this.asm.set_iv(ivview.getUint32(0), ivview.getUint32(4), ivview.getUint32(8), ivview.getUint32(12));
            }
            else {
                this.asm.set_iv(0, 0, 0, 0);
            }
            this.padding = padding;
        }
        AES_Encrypt_process(data) {
            if (!is_bytes(data))
                throw new TypeError("data isn't of expected type");
            let asm = this.asm;
            let heap = this.heap;
            let amode = AES_asm.ENC[this.mode];
            let hpos = AES_asm.HEAP_DATA;
            let pos = this.pos;
            let len = this.len;
            let dpos = 0;
            let dlen = data.length || 0;
            let rpos = 0;
            let rlen = (len + dlen) & -16;
            let wlen = 0;
            let result = new Uint8Array(rlen);
            while (dlen > 0) {
                wlen = _heap_write(heap, pos + len, data, dpos, dlen);
                len += wlen;
                dpos += wlen;
                dlen -= wlen;
                wlen = asm.cipher(amode, hpos + pos, len);
                if (wlen)
                    result.set(heap.subarray(pos, pos + wlen), rpos);
                rpos += wlen;
                if (wlen < len) {
                    pos += wlen;
                    len -= wlen;
                }
                else {
                    pos = 0;
                    len = 0;
                }
            }
            this.pos = pos;
            this.len = len;
            return result;
        }
        AES_Encrypt_finish() {
            let asm = this.asm;
            let heap = this.heap;
            let amode = AES_asm.ENC[this.mode];
            let hpos = AES_asm.HEAP_DATA;
            let pos = this.pos;
            let len = this.len;
            let plen = 16 - (len % 16);
            let rlen = len;
            if (this.hasOwnProperty('padding')) {
                if (this.padding) {
                    for (let p = 0; p < plen; ++p) {
                        heap[pos + len + p] = plen;
                    }
                    len += plen;
                    rlen = len;
                }
                else if (len % 16) {
                    throw new IllegalArgumentError('data length must be a multiple of the block size');
                }
            }
            else {
                len += plen;
            }
            const result = new Uint8Array(rlen);
            if (len)
                asm.cipher(amode, hpos + pos, len);
            if (rlen)
                result.set(heap.subarray(pos, pos + rlen));
            this.pos = 0;
            this.len = 0;
            return result;
        }
        AES_Decrypt_process(data) {
            if (!is_bytes(data))
                throw new TypeError("data isn't of expected type");
            let asm = this.asm;
            let heap = this.heap;
            let amode = AES_asm.DEC[this.mode];
            let hpos = AES_asm.HEAP_DATA;
            let pos = this.pos;
            let len = this.len;
            let dpos = 0;
            let dlen = data.length || 0;
            let rpos = 0;
            let rlen = (len + dlen) & -16;
            let plen = 0;
            let wlen = 0;
            if (this.padding) {
                plen = len + dlen - rlen || 16;
                rlen -= plen;
            }
            const result = new Uint8Array(rlen);
            while (dlen > 0) {
                wlen = _heap_write(heap, pos + len, data, dpos, dlen);
                len += wlen;
                dpos += wlen;
                dlen -= wlen;
                wlen = asm.cipher(amode, hpos + pos, len - (!dlen ? plen : 0));
                if (wlen)
                    result.set(heap.subarray(pos, pos + wlen), rpos);
                rpos += wlen;
                if (wlen < len) {
                    pos += wlen;
                    len -= wlen;
                }
                else {
                    pos = 0;
                    len = 0;
                }
            }
            this.pos = pos;
            this.len = len;
            return result;
        }
        AES_Decrypt_finish() {
            let asm = this.asm;
            let heap = this.heap;
            let amode = AES_asm.DEC[this.mode];
            let hpos = AES_asm.HEAP_DATA;
            let pos = this.pos;
            let len = this.len;
            let rlen = len;
            if (len > 0) {
                if (len % 16) {
                    if (this.hasOwnProperty('padding')) {
                        throw new IllegalArgumentError('data length must be a multiple of the block size');
                    }
                    else {
                        len += 16 - (len % 16);
                    }
                }
                asm.cipher(amode, hpos + pos, len);
                if (this.hasOwnProperty('padding') && this.padding) {
                    let pad = heap[pos + rlen - 1];
                    if (pad < 1 || pad > 16 || pad > rlen)
                        throw new SecurityError('bad padding');
                    let pcheck = 0;
                    for (let i = pad; i > 1; i--)
                        pcheck |= pad ^ heap[pos + rlen - i];
                    if (pcheck)
                        throw new SecurityError('bad padding');
                    rlen -= pad;
                }
            }
            const result = new Uint8Array(rlen);
            if (rlen > 0) {
                result.set(heap.subarray(pos, pos + rlen));
            }
            this.pos = 0;
            this.len = 0;
            return result;
        }
    }

    class AES_CBC extends AES {
        static encrypt(data, key, padding = true, iv) {
            return new AES_CBC(key, iv, padding).encrypt(data);
        }
        static decrypt(data, key, padding = true, iv) {
            return new AES_CBC(key, iv, padding).decrypt(data);
        }
        constructor(key, iv, padding = true) {
            super(key, iv, padding, 'CBC');
        }
        encrypt(data) {
            const r1 = this.AES_Encrypt_process(data);
            const r2 = this.AES_Encrypt_finish();
            return joinBytes(r1, r2);
        }
        decrypt(data) {
            const r1 = this.AES_Decrypt_process(data);
            const r2 = this.AES_Decrypt_finish();
            return joinBytes(r1, r2);
        }
    }

    /**
     * Integers are represented as little endian array of 32-bit limbs.
     * Limbs number is a power of 2 and a multiple of 8 (256 bits).
     * Negative values use two's complement representation.
     */
    var bigint_asm = function ( stdlib, foreign, buffer ) {
        "use asm";

        var SP = 0;

        var HEAP32 = new stdlib.Uint32Array(buffer);

        var imul = stdlib.Math.imul;

        /**
         * Simple stack memory allocator
         *
         * Methods:
         *  sreset
         *  salloc
         *  sfree
         */

        function sreset ( p ) {
            p = p|0;
            SP = p = (p + 31) & -32;
            return p|0;
        }

        function salloc ( l ) {
            l = l|0;
            var p = 0; p = SP;
            SP = p + ((l + 31) & -32)|0;
            return p|0;
        }

        function sfree ( l ) {
            l = l|0;
            SP = SP - ((l + 31) & -32)|0;
        }

        /**
         * Utility functions:
         *  cp
         *  z
         */

        function cp ( l, A, B ) {
            l = l|0;
            A = A|0;
            B = B|0;

            var i = 0;

            if ( (A|0) > (B|0) ) {
                for ( ; (i|0) < (l|0); i = (i+4)|0 ) {
                    HEAP32[(B+i)>>2] = HEAP32[(A+i)>>2];
                }
            }
            else {
                for ( i = (l-4)|0; (i|0) >= 0; i = (i-4)|0 ) {
                    HEAP32[(B+i)>>2] = HEAP32[(A+i)>>2];
                }
            }
        }

        function z ( l, z, A ) {
            l = l|0;
            z = z|0;
            A = A|0;

            var i = 0;

            for ( ; (i|0) < (l|0); i = (i+4)|0 ) {
                HEAP32[(A+i)>>2] = z;
            }
        }

        /**
         * Negate the argument
         *
         * Perform two's complement transformation:
         *
         *  -A = ~A + 1
         *
         * @param A offset of the argment being negated, 32-byte aligned
         * @param lA length of the argument, multiple of 32
         *
         * @param R offset where to place the result to, 32-byte aligned
         * @param lR length to truncate the result to, multiple of 32
         */
        function neg ( A, lA, R, lR ) {
            A  =  A|0;
            lA = lA|0;
            R  =  R|0;
            lR = lR|0;

            var a = 0, c = 0, t = 0, r = 0, i = 0;

            if ( (lR|0) <= 0 )
                lR = lA;

            if ( (lR|0) < (lA|0) )
                lA = lR;

            c = 1;
            for ( ; (i|0) < (lA|0); i = (i+4)|0 ) {
                a = ~HEAP32[(A+i)>>2];
                t = (a & 0xffff) + c|0;
                r = (a >>> 16) + (t >>> 16)|0;
                HEAP32[(R+i)>>2] = (r << 16) | (t & 0xffff);
                c = r >>> 16;
            }

            for ( ; (i|0) < (lR|0); i = (i+4)|0 ) {
                HEAP32[(R+i)>>2] = (c-1)|0;
            }

            return c|0;
        }

        function cmp ( A, lA, B, lB ) {
            A  =  A|0;
            lA = lA|0;
            B  =  B|0;
            lB = lB|0;

            var a = 0, b = 0, i = 0;

            if ( (lA|0) > (lB|0) ) {
                for ( i = (lA-4)|0; (i|0) >= (lB|0); i = (i-4)|0 ) {
                    if ( HEAP32[(A+i)>>2]|0 ) return 1;
                }
            }
            else {
                for ( i = (lB-4)|0; (i|0) >= (lA|0); i = (i-4)|0 ) {
                    if ( HEAP32[(B+i)>>2]|0 ) return -1;
                }
            }

            for ( ; (i|0) >= 0; i = (i-4)|0 ) {
                a = HEAP32[(A+i)>>2]|0, b = HEAP32[(B+i)>>2]|0;
                if ( (a>>>0) < (b>>>0) ) return -1;
                if ( (a>>>0) > (b>>>0) ) return 1;
            }

            return 0;
        }

        /**
         * Test the argument
         *
         * Same as `cmp` with zero.
         */
        function tst ( A, lA ) {
            A  =  A|0;
            lA = lA|0;

            var i = 0;

            for ( i = (lA-4)|0; (i|0) >= 0; i = (i-4)|0 ) {
                if ( HEAP32[(A+i)>>2]|0 ) return (i+4)|0;
            }

            return 0;
        }

        /**
         * Conventional addition
         *
         * @param A offset of the first argument, 32-byte aligned
         * @param lA length of the first argument, multiple of 32
         *
         * @param B offset of the second argument, 32-bit aligned
         * @param lB length of the second argument, multiple of 32
         *
         * @param R offset where to place the result to, 32-byte aligned
         * @param lR length to truncate the result to, multiple of 32
         */
        function add ( A, lA, B, lB, R, lR ) {
            A  =  A|0;
            lA = lA|0;
            B  =  B|0;
            lB = lB|0;
            R  =  R|0;
            lR = lR|0;

            var a = 0, b = 0, c = 0, t = 0, r = 0, i = 0;

            if ( (lA|0) < (lB|0) ) {
                t = A, A = B, B = t;
                t = lA, lA = lB, lB = t;
            }

            if ( (lR|0) <= 0 )
                lR = lA+4|0;

            if ( (lR|0) < (lB|0) )
                lA = lB = lR;

            for ( ; (i|0) < (lB|0); i = (i+4)|0 ) {
                a = HEAP32[(A+i)>>2]|0;
                b = HEAP32[(B+i)>>2]|0;
                t = ( (a & 0xffff) + (b & 0xffff)|0 ) + c|0;
                r = ( (a >>> 16) + (b >>> 16)|0 ) + (t >>> 16)|0;
                HEAP32[(R+i)>>2] = (t & 0xffff) | (r << 16);
                c = r >>> 16;
            }

            for ( ; (i|0) < (lA|0); i = (i+4)|0 ) {
                a = HEAP32[(A+i)>>2]|0;
                t = (a & 0xffff) + c|0;
                r = (a >>> 16) + (t >>> 16)|0;
                HEAP32[(R+i)>>2] = (t & 0xffff) | (r << 16);
                c = r >>> 16;
            }

            for ( ; (i|0) < (lR|0); i = (i+4)|0 ) {
                HEAP32[(R+i)>>2] = c|0;
                c = 0;
            }

            return c|0;
        }

       /**
         * Conventional subtraction
         *
         * @param A offset of the first argument, 32-byte aligned
         * @param lA length of the first argument, multiple of 32
         *
         * @param B offset of the second argument, 32-bit aligned
         * @param lB length of the second argument, multiple of 32
         *
         * @param R offset where to place the result to, 32-byte aligned
         * @param lR length to truncate the result to, multiple of 32
         */
        function sub ( A, lA, B, lB, R, lR ) {
            A  =  A|0;
            lA = lA|0;
            B  =  B|0;
            lB = lB|0;
            R  =  R|0;
            lR = lR|0;

            var a = 0, b = 0, c = 0, t = 0, r = 0, i = 0;

            if ( (lR|0) <= 0 )
                lR = (lA|0) > (lB|0) ? lA+4|0 : lB+4|0;

            if ( (lR|0) < (lA|0) )
                lA = lR;

            if ( (lR|0) < (lB|0) )
                lB = lR;

            if ( (lA|0) < (lB|0) ) {
                for ( ; (i|0) < (lA|0); i = (i+4)|0 ) {
                    a = HEAP32[(A+i)>>2]|0;
                    b = HEAP32[(B+i)>>2]|0;
                    t = ( (a & 0xffff) - (b & 0xffff)|0 ) + c|0;
                    r = ( (a >>> 16) - (b >>> 16)|0 ) + (t >> 16)|0;
                    HEAP32[(R+i)>>2] = (t & 0xffff) | (r << 16);
                    c = r >> 16;
                }

                for ( ; (i|0) < (lB|0); i = (i+4)|0 ) {
                    b = HEAP32[(B+i)>>2]|0;
                    t = c - (b & 0xffff)|0;
                    r = (t >> 16) - (b >>> 16)|0;
                    HEAP32[(R+i)>>2] = (t & 0xffff) | (r << 16);
                    c = r >> 16;
                }
            }
            else {
                for ( ; (i|0) < (lB|0); i = (i+4)|0 ) {
                    a = HEAP32[(A+i)>>2]|0;
                    b = HEAP32[(B+i)>>2]|0;
                    t = ( (a & 0xffff) - (b & 0xffff)|0 ) + c|0;
                    r = ( (a >>> 16) - (b >>> 16)|0 ) + (t >> 16)|0;
                    HEAP32[(R+i)>>2] = (t & 0xffff) | (r << 16);
                    c = r >> 16;
                }

                for ( ; (i|0) < (lA|0); i = (i+4)|0 ) {
                    a = HEAP32[(A+i)>>2]|0;
                    t = (a & 0xffff) + c|0;
                    r = (a >>> 16) + (t >> 16)|0;
                    HEAP32[(R+i)>>2] = (t & 0xffff) | (r << 16);
                    c = r >> 16;
                }
            }

            for ( ; (i|0) < (lR|0); i = (i+4)|0 ) {
                HEAP32[(R+i)>>2] = c|0;
            }

            return c|0;
        }

        /**
         * Conventional multiplication
         *
         * TODO implement Karatsuba algorithm for large multiplicands
         *
         * @param A offset of the first argument, 32-byte aligned
         * @param lA length of the first argument, multiple of 32
         *
         * @param B offset of the second argument, 32-byte aligned
         * @param lB length of the second argument, multiple of 32
         *
         * @param R offset where to place the result to, 32-byte aligned
         * @param lR length to truncate the result to, multiple of 32
         */
        function mul ( A, lA, B, lB, R, lR ) {
            A  =  A|0;
            lA = lA|0;
            B  =  B|0;
            lB = lB|0;
            R  =  R|0;
            lR = lR|0;

            var al0 = 0, al1 = 0, al2 = 0, al3 = 0, al4 = 0, al5 = 0, al6 = 0, al7 = 0, ah0 = 0, ah1 = 0, ah2 = 0, ah3 = 0, ah4 = 0, ah5 = 0, ah6 = 0, ah7 = 0,
                bl0 = 0, bl1 = 0, bl2 = 0, bl3 = 0, bl4 = 0, bl5 = 0, bl6 = 0, bl7 = 0, bh0 = 0, bh1 = 0, bh2 = 0, bh3 = 0, bh4 = 0, bh5 = 0, bh6 = 0, bh7 = 0,
                r0 = 0, r1 = 0, r2 = 0, r3 = 0, r4 = 0, r5 = 0, r6 = 0, r7 = 0, r8 = 0, r9 = 0, r10 = 0, r11 = 0, r12 = 0, r13 = 0, r14 = 0, r15 = 0,
                u = 0, v = 0, w = 0, m = 0,
                i = 0, Ai = 0, j = 0, Bj = 0, Rk = 0;

            if ( (lA|0) > (lB|0) ) {
                u = A, v = lA;
                A = B, lA = lB;
                B = u, lB = v;
            }

            m = (lA+lB)|0;
            if ( ( (lR|0) > (m|0) ) | ( (lR|0) <= 0 ) )
                lR = m;

            if ( (lR|0) < (lA|0) )
                lA = lR;

            if ( (lR|0) < (lB|0) )
                lB = lR;

            for ( ; (i|0) < (lA|0); i = (i+32)|0 ) {
                Ai = (A+i)|0;

                ah0 = HEAP32[(Ai|0)>>2]|0,
                ah1 = HEAP32[(Ai|4)>>2]|0,
                ah2 = HEAP32[(Ai|8)>>2]|0,
                ah3 = HEAP32[(Ai|12)>>2]|0,
                ah4 = HEAP32[(Ai|16)>>2]|0,
                ah5 = HEAP32[(Ai|20)>>2]|0,
                ah6 = HEAP32[(Ai|24)>>2]|0,
                ah7 = HEAP32[(Ai|28)>>2]|0,
                al0 = ah0 & 0xffff,
                al1 = ah1 & 0xffff,
                al2 = ah2 & 0xffff,
                al3 = ah3 & 0xffff,
                al4 = ah4 & 0xffff,
                al5 = ah5 & 0xffff,
                al6 = ah6 & 0xffff,
                al7 = ah7 & 0xffff,
                ah0 = ah0 >>> 16,
                ah1 = ah1 >>> 16,
                ah2 = ah2 >>> 16,
                ah3 = ah3 >>> 16,
                ah4 = ah4 >>> 16,
                ah5 = ah5 >>> 16,
                ah6 = ah6 >>> 16,
                ah7 = ah7 >>> 16;

                r8 = r9 = r10 = r11 = r12 = r13 = r14 = r15 = 0;

                for ( j = 0; (j|0) < (lB|0); j = (j+32)|0 ) {
                    Bj = (B+j)|0;
                    Rk = (R+(i+j|0))|0;

                    bh0 = HEAP32[(Bj|0)>>2]|0,
                    bh1 = HEAP32[(Bj|4)>>2]|0,
                    bh2 = HEAP32[(Bj|8)>>2]|0,
                    bh3 = HEAP32[(Bj|12)>>2]|0,
                    bh4 = HEAP32[(Bj|16)>>2]|0,
                    bh5 = HEAP32[(Bj|20)>>2]|0,
                    bh6 = HEAP32[(Bj|24)>>2]|0,
                    bh7 = HEAP32[(Bj|28)>>2]|0,
                    bl0 = bh0 & 0xffff,
                    bl1 = bh1 & 0xffff,
                    bl2 = bh2 & 0xffff,
                    bl3 = bh3 & 0xffff,
                    bl4 = bh4 & 0xffff,
                    bl5 = bh5 & 0xffff,
                    bl6 = bh6 & 0xffff,
                    bl7 = bh7 & 0xffff,
                    bh0 = bh0 >>> 16,
                    bh1 = bh1 >>> 16,
                    bh2 = bh2 >>> 16,
                    bh3 = bh3 >>> 16,
                    bh4 = bh4 >>> 16,
                    bh5 = bh5 >>> 16,
                    bh6 = bh6 >>> 16,
                    bh7 = bh7 >>> 16;

                    r0 = HEAP32[(Rk|0)>>2]|0,
                    r1 = HEAP32[(Rk|4)>>2]|0,
                    r2 = HEAP32[(Rk|8)>>2]|0,
                    r3 = HEAP32[(Rk|12)>>2]|0,
                    r4 = HEAP32[(Rk|16)>>2]|0,
                    r5 = HEAP32[(Rk|20)>>2]|0,
                    r6 = HEAP32[(Rk|24)>>2]|0,
                    r7 = HEAP32[(Rk|28)>>2]|0;

                    u = ((imul(al0, bl0)|0) + (r8 & 0xffff)|0) + (r0 & 0xffff)|0;
                    v = ((imul(ah0, bl0)|0) + (r8 >>> 16)|0) + (r0 >>> 16)|0;
                    w = ((imul(al0, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah0, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r0 = (w << 16) | (u & 0xffff);

                    u = ((imul(al0, bl1)|0) + (m & 0xffff)|0) + (r1 & 0xffff)|0;
                    v = ((imul(ah0, bl1)|0) + (m >>> 16)|0) + (r1 >>> 16)|0;
                    w = ((imul(al0, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah0, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r1 = (w << 16) | (u & 0xffff);

                    u = ((imul(al0, bl2)|0) + (m & 0xffff)|0) + (r2 & 0xffff)|0;
                    v = ((imul(ah0, bl2)|0) + (m >>> 16)|0) + (r2 >>> 16)|0;
                    w = ((imul(al0, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah0, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r2 = (w << 16) | (u & 0xffff);

                    u = ((imul(al0, bl3)|0) + (m & 0xffff)|0) + (r3 & 0xffff)|0;
                    v = ((imul(ah0, bl3)|0) + (m >>> 16)|0) + (r3 >>> 16)|0;
                    w = ((imul(al0, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah0, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r3 = (w << 16) | (u & 0xffff);

                    u = ((imul(al0, bl4)|0) + (m & 0xffff)|0) + (r4 & 0xffff)|0;
                    v = ((imul(ah0, bl4)|0) + (m >>> 16)|0) + (r4 >>> 16)|0;
                    w = ((imul(al0, bh4)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah0, bh4)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r4 = (w << 16) | (u & 0xffff);

                    u = ((imul(al0, bl5)|0) + (m & 0xffff)|0) + (r5 & 0xffff)|0;
                    v = ((imul(ah0, bl5)|0) + (m >>> 16)|0) + (r5 >>> 16)|0;
                    w = ((imul(al0, bh5)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah0, bh5)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r5 = (w << 16) | (u & 0xffff);

                    u = ((imul(al0, bl6)|0) + (m & 0xffff)|0) + (r6 & 0xffff)|0;
                    v = ((imul(ah0, bl6)|0) + (m >>> 16)|0) + (r6 >>> 16)|0;
                    w = ((imul(al0, bh6)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah0, bh6)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r6 = (w << 16) | (u & 0xffff);

                    u = ((imul(al0, bl7)|0) + (m & 0xffff)|0) + (r7 & 0xffff)|0;
                    v = ((imul(ah0, bl7)|0) + (m >>> 16)|0) + (r7 >>> 16)|0;
                    w = ((imul(al0, bh7)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah0, bh7)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r7 = (w << 16) | (u & 0xffff);

                    r8 = m;

                    u = ((imul(al1, bl0)|0) + (r9 & 0xffff)|0) + (r1 & 0xffff)|0;
                    v = ((imul(ah1, bl0)|0) + (r9 >>> 16)|0) + (r1 >>> 16)|0;
                    w = ((imul(al1, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah1, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r1 = (w << 16) | (u & 0xffff);

                    u = ((imul(al1, bl1)|0) + (m & 0xffff)|0) + (r2 & 0xffff)|0;
                    v = ((imul(ah1, bl1)|0) + (m >>> 16)|0) + (r2 >>> 16)|0;
                    w = ((imul(al1, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah1, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r2 = (w << 16) | (u & 0xffff);

                    u = ((imul(al1, bl2)|0) + (m & 0xffff)|0) + (r3 & 0xffff)|0;
                    v = ((imul(ah1, bl2)|0) + (m >>> 16)|0) + (r3 >>> 16)|0;
                    w = ((imul(al1, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah1, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r3 = (w << 16) | (u & 0xffff);

                    u = ((imul(al1, bl3)|0) + (m & 0xffff)|0) + (r4 & 0xffff)|0;
                    v = ((imul(ah1, bl3)|0) + (m >>> 16)|0) + (r4 >>> 16)|0;
                    w = ((imul(al1, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah1, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r4 = (w << 16) | (u & 0xffff);

                    u = ((imul(al1, bl4)|0) + (m & 0xffff)|0) + (r5 & 0xffff)|0;
                    v = ((imul(ah1, bl4)|0) + (m >>> 16)|0) + (r5 >>> 16)|0;
                    w = ((imul(al1, bh4)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah1, bh4)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r5 = (w << 16) | (u & 0xffff);

                    u = ((imul(al1, bl5)|0) + (m & 0xffff)|0) + (r6 & 0xffff)|0;
                    v = ((imul(ah1, bl5)|0) + (m >>> 16)|0) + (r6 >>> 16)|0;
                    w = ((imul(al1, bh5)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah1, bh5)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r6 = (w << 16) | (u & 0xffff);

                    u = ((imul(al1, bl6)|0) + (m & 0xffff)|0) + (r7 & 0xffff)|0;
                    v = ((imul(ah1, bl6)|0) + (m >>> 16)|0) + (r7 >>> 16)|0;
                    w = ((imul(al1, bh6)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah1, bh6)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r7 = (w << 16) | (u & 0xffff);

                    u = ((imul(al1, bl7)|0) + (m & 0xffff)|0) + (r8 & 0xffff)|0;
                    v = ((imul(ah1, bl7)|0) + (m >>> 16)|0) + (r8 >>> 16)|0;
                    w = ((imul(al1, bh7)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah1, bh7)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r8 = (w << 16) | (u & 0xffff);

                    r9 = m;

                    u = ((imul(al2, bl0)|0) + (r10 & 0xffff)|0) + (r2 & 0xffff)|0;
                    v = ((imul(ah2, bl0)|0) + (r10 >>> 16)|0) + (r2 >>> 16)|0;
                    w = ((imul(al2, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah2, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r2 = (w << 16) | (u & 0xffff);

                    u = ((imul(al2, bl1)|0) + (m & 0xffff)|0) + (r3 & 0xffff)|0;
                    v = ((imul(ah2, bl1)|0) + (m >>> 16)|0) + (r3 >>> 16)|0;
                    w = ((imul(al2, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah2, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r3 = (w << 16) | (u & 0xffff);

                    u = ((imul(al2, bl2)|0) + (m & 0xffff)|0) + (r4 & 0xffff)|0;
                    v = ((imul(ah2, bl2)|0) + (m >>> 16)|0) + (r4 >>> 16)|0;
                    w = ((imul(al2, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah2, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r4 = (w << 16) | (u & 0xffff);

                    u = ((imul(al2, bl3)|0) + (m & 0xffff)|0) + (r5 & 0xffff)|0;
                    v = ((imul(ah2, bl3)|0) + (m >>> 16)|0) + (r5 >>> 16)|0;
                    w = ((imul(al2, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah2, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r5 = (w << 16) | (u & 0xffff);

                    u = ((imul(al2, bl4)|0) + (m & 0xffff)|0) + (r6 & 0xffff)|0;
                    v = ((imul(ah2, bl4)|0) + (m >>> 16)|0) + (r6 >>> 16)|0;
                    w = ((imul(al2, bh4)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah2, bh4)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r6 = (w << 16) | (u & 0xffff);

                    u = ((imul(al2, bl5)|0) + (m & 0xffff)|0) + (r7 & 0xffff)|0;
                    v = ((imul(ah2, bl5)|0) + (m >>> 16)|0) + (r7 >>> 16)|0;
                    w = ((imul(al2, bh5)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah2, bh5)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r7 = (w << 16) | (u & 0xffff);

                    u = ((imul(al2, bl6)|0) + (m & 0xffff)|0) + (r8 & 0xffff)|0;
                    v = ((imul(ah2, bl6)|0) + (m >>> 16)|0) + (r8 >>> 16)|0;
                    w = ((imul(al2, bh6)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah2, bh6)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r8 = (w << 16) | (u & 0xffff);

                    u = ((imul(al2, bl7)|0) + (m & 0xffff)|0) + (r9 & 0xffff)|0;
                    v = ((imul(ah2, bl7)|0) + (m >>> 16)|0) + (r9 >>> 16)|0;
                    w = ((imul(al2, bh7)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah2, bh7)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r9 = (w << 16) | (u & 0xffff);

                    r10 = m;

                    u = ((imul(al3, bl0)|0) + (r11 & 0xffff)|0) + (r3 & 0xffff)|0;
                    v = ((imul(ah3, bl0)|0) + (r11 >>> 16)|0) + (r3 >>> 16)|0;
                    w = ((imul(al3, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah3, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r3 = (w << 16) | (u & 0xffff);

                    u = ((imul(al3, bl1)|0) + (m & 0xffff)|0) + (r4 & 0xffff)|0;
                    v = ((imul(ah3, bl1)|0) + (m >>> 16)|0) + (r4 >>> 16)|0;
                    w = ((imul(al3, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah3, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r4 = (w << 16) | (u & 0xffff);

                    u = ((imul(al3, bl2)|0) + (m & 0xffff)|0) + (r5 & 0xffff)|0;
                    v = ((imul(ah3, bl2)|0) + (m >>> 16)|0) + (r5 >>> 16)|0;
                    w = ((imul(al3, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah3, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r5 = (w << 16) | (u & 0xffff);

                    u = ((imul(al3, bl3)|0) + (m & 0xffff)|0) + (r6 & 0xffff)|0;
                    v = ((imul(ah3, bl3)|0) + (m >>> 16)|0) + (r6 >>> 16)|0;
                    w = ((imul(al3, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah3, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r6 = (w << 16) | (u & 0xffff);

                    u = ((imul(al3, bl4)|0) + (m & 0xffff)|0) + (r7 & 0xffff)|0;
                    v = ((imul(ah3, bl4)|0) + (m >>> 16)|0) + (r7 >>> 16)|0;
                    w = ((imul(al3, bh4)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah3, bh4)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r7 = (w << 16) | (u & 0xffff);

                    u = ((imul(al3, bl5)|0) + (m & 0xffff)|0) + (r8 & 0xffff)|0;
                    v = ((imul(ah3, bl5)|0) + (m >>> 16)|0) + (r8 >>> 16)|0;
                    w = ((imul(al3, bh5)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah3, bh5)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r8 = (w << 16) | (u & 0xffff);

                    u = ((imul(al3, bl6)|0) + (m & 0xffff)|0) + (r9 & 0xffff)|0;
                    v = ((imul(ah3, bl6)|0) + (m >>> 16)|0) + (r9 >>> 16)|0;
                    w = ((imul(al3, bh6)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah3, bh6)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r9 = (w << 16) | (u & 0xffff);

                    u = ((imul(al3, bl7)|0) + (m & 0xffff)|0) + (r10 & 0xffff)|0;
                    v = ((imul(ah3, bl7)|0) + (m >>> 16)|0) + (r10 >>> 16)|0;
                    w = ((imul(al3, bh7)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah3, bh7)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r10 = (w << 16) | (u & 0xffff);

                    r11 = m;

                    u = ((imul(al4, bl0)|0) + (r12 & 0xffff)|0) + (r4 & 0xffff)|0;
                    v = ((imul(ah4, bl0)|0) + (r12 >>> 16)|0) + (r4 >>> 16)|0;
                    w = ((imul(al4, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah4, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r4 = (w << 16) | (u & 0xffff);

                    u = ((imul(al4, bl1)|0) + (m & 0xffff)|0) + (r5 & 0xffff)|0;
                    v = ((imul(ah4, bl1)|0) + (m >>> 16)|0) + (r5 >>> 16)|0;
                    w = ((imul(al4, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah4, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r5 = (w << 16) | (u & 0xffff);

                    u = ((imul(al4, bl2)|0) + (m & 0xffff)|0) + (r6 & 0xffff)|0;
                    v = ((imul(ah4, bl2)|0) + (m >>> 16)|0) + (r6 >>> 16)|0;
                    w = ((imul(al4, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah4, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r6 = (w << 16) | (u & 0xffff);

                    u = ((imul(al4, bl3)|0) + (m & 0xffff)|0) + (r7 & 0xffff)|0;
                    v = ((imul(ah4, bl3)|0) + (m >>> 16)|0) + (r7 >>> 16)|0;
                    w = ((imul(al4, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah4, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r7 = (w << 16) | (u & 0xffff);

                    u = ((imul(al4, bl4)|0) + (m & 0xffff)|0) + (r8 & 0xffff)|0;
                    v = ((imul(ah4, bl4)|0) + (m >>> 16)|0) + (r8 >>> 16)|0;
                    w = ((imul(al4, bh4)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah4, bh4)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r8 = (w << 16) | (u & 0xffff);

                    u = ((imul(al4, bl5)|0) + (m & 0xffff)|0) + (r9 & 0xffff)|0;
                    v = ((imul(ah4, bl5)|0) + (m >>> 16)|0) + (r9 >>> 16)|0;
                    w = ((imul(al4, bh5)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah4, bh5)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r9 = (w << 16) | (u & 0xffff);

                    u = ((imul(al4, bl6)|0) + (m & 0xffff)|0) + (r10 & 0xffff)|0;
                    v = ((imul(ah4, bl6)|0) + (m >>> 16)|0) + (r10 >>> 16)|0;
                    w = ((imul(al4, bh6)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah4, bh6)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r10 = (w << 16) | (u & 0xffff);

                    u = ((imul(al4, bl7)|0) + (m & 0xffff)|0) + (r11 & 0xffff)|0;
                    v = ((imul(ah4, bl7)|0) + (m >>> 16)|0) + (r11 >>> 16)|0;
                    w = ((imul(al4, bh7)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah4, bh7)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r11 = (w << 16) | (u & 0xffff);

                    r12 = m;

                    u = ((imul(al5, bl0)|0) + (r13 & 0xffff)|0) + (r5 & 0xffff)|0;
                    v = ((imul(ah5, bl0)|0) + (r13 >>> 16)|0) + (r5 >>> 16)|0;
                    w = ((imul(al5, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah5, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r5 = (w << 16) | (u & 0xffff);

                    u = ((imul(al5, bl1)|0) + (m & 0xffff)|0) + (r6 & 0xffff)|0;
                    v = ((imul(ah5, bl1)|0) + (m >>> 16)|0) + (r6 >>> 16)|0;
                    w = ((imul(al5, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah5, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r6 = (w << 16) | (u & 0xffff);

                    u = ((imul(al5, bl2)|0) + (m & 0xffff)|0) + (r7 & 0xffff)|0;
                    v = ((imul(ah5, bl2)|0) + (m >>> 16)|0) + (r7 >>> 16)|0;
                    w = ((imul(al5, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah5, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r7 = (w << 16) | (u & 0xffff);

                    u = ((imul(al5, bl3)|0) + (m & 0xffff)|0) + (r8 & 0xffff)|0;
                    v = ((imul(ah5, bl3)|0) + (m >>> 16)|0) + (r8 >>> 16)|0;
                    w = ((imul(al5, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah5, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r8 = (w << 16) | (u & 0xffff);

                    u = ((imul(al5, bl4)|0) + (m & 0xffff)|0) + (r9 & 0xffff)|0;
                    v = ((imul(ah5, bl4)|0) + (m >>> 16)|0) + (r9 >>> 16)|0;
                    w = ((imul(al5, bh4)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah5, bh4)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r9 = (w << 16) | (u & 0xffff);

                    u = ((imul(al5, bl5)|0) + (m & 0xffff)|0) + (r10 & 0xffff)|0;
                    v = ((imul(ah5, bl5)|0) + (m >>> 16)|0) + (r10 >>> 16)|0;
                    w = ((imul(al5, bh5)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah5, bh5)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r10 = (w << 16) | (u & 0xffff);

                    u = ((imul(al5, bl6)|0) + (m & 0xffff)|0) + (r11 & 0xffff)|0;
                    v = ((imul(ah5, bl6)|0) + (m >>> 16)|0) + (r11 >>> 16)|0;
                    w = ((imul(al5, bh6)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah5, bh6)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r11 = (w << 16) | (u & 0xffff);

                    u = ((imul(al5, bl7)|0) + (m & 0xffff)|0) + (r12 & 0xffff)|0;
                    v = ((imul(ah5, bl7)|0) + (m >>> 16)|0) + (r12 >>> 16)|0;
                    w = ((imul(al5, bh7)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah5, bh7)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r12 = (w << 16) | (u & 0xffff);

                    r13 = m;

                    u = ((imul(al6, bl0)|0) + (r14 & 0xffff)|0) + (r6 & 0xffff)|0;
                    v = ((imul(ah6, bl0)|0) + (r14 >>> 16)|0) + (r6 >>> 16)|0;
                    w = ((imul(al6, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah6, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r6 = (w << 16) | (u & 0xffff);

                    u = ((imul(al6, bl1)|0) + (m & 0xffff)|0) + (r7 & 0xffff)|0;
                    v = ((imul(ah6, bl1)|0) + (m >>> 16)|0) + (r7 >>> 16)|0;
                    w = ((imul(al6, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah6, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r7 = (w << 16) | (u & 0xffff);

                    u = ((imul(al6, bl2)|0) + (m & 0xffff)|0) + (r8 & 0xffff)|0;
                    v = ((imul(ah6, bl2)|0) + (m >>> 16)|0) + (r8 >>> 16)|0;
                    w = ((imul(al6, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah6, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r8 = (w << 16) | (u & 0xffff);

                    u = ((imul(al6, bl3)|0) + (m & 0xffff)|0) + (r9 & 0xffff)|0;
                    v = ((imul(ah6, bl3)|0) + (m >>> 16)|0) + (r9 >>> 16)|0;
                    w = ((imul(al6, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah6, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r9 = (w << 16) | (u & 0xffff);

                    u = ((imul(al6, bl4)|0) + (m & 0xffff)|0) + (r10 & 0xffff)|0;
                    v = ((imul(ah6, bl4)|0) + (m >>> 16)|0) + (r10 >>> 16)|0;
                    w = ((imul(al6, bh4)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah6, bh4)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r10 = (w << 16) | (u & 0xffff);

                    u = ((imul(al6, bl5)|0) + (m & 0xffff)|0) + (r11 & 0xffff)|0;
                    v = ((imul(ah6, bl5)|0) + (m >>> 16)|0) + (r11 >>> 16)|0;
                    w = ((imul(al6, bh5)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah6, bh5)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r11 = (w << 16) | (u & 0xffff);

                    u = ((imul(al6, bl6)|0) + (m & 0xffff)|0) + (r12 & 0xffff)|0;
                    v = ((imul(ah6, bl6)|0) + (m >>> 16)|0) + (r12 >>> 16)|0;
                    w = ((imul(al6, bh6)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah6, bh6)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r12 = (w << 16) | (u & 0xffff);

                    u = ((imul(al6, bl7)|0) + (m & 0xffff)|0) + (r13 & 0xffff)|0;
                    v = ((imul(ah6, bl7)|0) + (m >>> 16)|0) + (r13 >>> 16)|0;
                    w = ((imul(al6, bh7)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah6, bh7)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r13 = (w << 16) | (u & 0xffff);

                    r14 = m;

                    u = ((imul(al7, bl0)|0) + (r15 & 0xffff)|0) + (r7 & 0xffff)|0;
                    v = ((imul(ah7, bl0)|0) + (r15 >>> 16)|0) + (r7 >>> 16)|0;
                    w = ((imul(al7, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah7, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r7 = (w << 16) | (u & 0xffff);

                    u = ((imul(al7, bl1)|0) + (m & 0xffff)|0) + (r8 & 0xffff)|0;
                    v = ((imul(ah7, bl1)|0) + (m >>> 16)|0) + (r8 >>> 16)|0;
                    w = ((imul(al7, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah7, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r8 = (w << 16) | (u & 0xffff);

                    u = ((imul(al7, bl2)|0) + (m & 0xffff)|0) + (r9 & 0xffff)|0;
                    v = ((imul(ah7, bl2)|0) + (m >>> 16)|0) + (r9 >>> 16)|0;
                    w = ((imul(al7, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah7, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r9 = (w << 16) | (u & 0xffff);

                    u = ((imul(al7, bl3)|0) + (m & 0xffff)|0) + (r10 & 0xffff)|0;
                    v = ((imul(ah7, bl3)|0) + (m >>> 16)|0) + (r10 >>> 16)|0;
                    w = ((imul(al7, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah7, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r10 = (w << 16) | (u & 0xffff);

                    u = ((imul(al7, bl4)|0) + (m & 0xffff)|0) + (r11 & 0xffff)|0;
                    v = ((imul(ah7, bl4)|0) + (m >>> 16)|0) + (r11 >>> 16)|0;
                    w = ((imul(al7, bh4)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah7, bh4)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r11 = (w << 16) | (u & 0xffff);

                    u = ((imul(al7, bl5)|0) + (m & 0xffff)|0) + (r12 & 0xffff)|0;
                    v = ((imul(ah7, bl5)|0) + (m >>> 16)|0) + (r12 >>> 16)|0;
                    w = ((imul(al7, bh5)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah7, bh5)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r12 = (w << 16) | (u & 0xffff);

                    u = ((imul(al7, bl6)|0) + (m & 0xffff)|0) + (r13 & 0xffff)|0;
                    v = ((imul(ah7, bl6)|0) + (m >>> 16)|0) + (r13 >>> 16)|0;
                    w = ((imul(al7, bh6)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah7, bh6)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r13 = (w << 16) | (u & 0xffff);

                    u = ((imul(al7, bl7)|0) + (m & 0xffff)|0) + (r14 & 0xffff)|0;
                    v = ((imul(ah7, bl7)|0) + (m >>> 16)|0) + (r14 >>> 16)|0;
                    w = ((imul(al7, bh7)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah7, bh7)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r14 = (w << 16) | (u & 0xffff);

                    r15 = m;

                    HEAP32[(Rk|0)>>2] = r0,
                    HEAP32[(Rk|4)>>2] = r1,
                    HEAP32[(Rk|8)>>2] = r2,
                    HEAP32[(Rk|12)>>2] = r3,
                    HEAP32[(Rk|16)>>2] = r4,
                    HEAP32[(Rk|20)>>2] = r5,
                    HEAP32[(Rk|24)>>2] = r6,
                    HEAP32[(Rk|28)>>2] = r7;
                }

                Rk = (R+(i+j|0))|0;
                HEAP32[(Rk|0)>>2] = r8,
                HEAP32[(Rk|4)>>2] = r9,
                HEAP32[(Rk|8)>>2] = r10,
                HEAP32[(Rk|12)>>2] = r11,
                HEAP32[(Rk|16)>>2] = r12,
                HEAP32[(Rk|20)>>2] = r13,
                HEAP32[(Rk|24)>>2] = r14,
                HEAP32[(Rk|28)>>2] = r15;
            }
    /*
            for ( i = lA & -32; (i|0) < (lA|0); i = (i+4)|0 ) {
                Ai = (A+i)|0;

                ah0 = HEAP32[Ai>>2]|0,
                al0 = ah0 & 0xffff,
                ah0 = ah0 >>> 16;

                r1 = 0;

                for ( j = 0; (j|0) < (lB|0); j = (j+4)|0 ) {
                    Bj = (B+j)|0;
                    Rk = (R+(i+j|0))|0;

                    bh0 = HEAP32[Bj>>2]|0,
                    bl0 = bh0 & 0xffff,
                    bh0 = bh0 >>> 16;

                    r0 = HEAP32[Rk>>2]|0;

                    u = ((imul(al0, bl0)|0) + (r1 & 0xffff)|0) + (r0 & 0xffff)|0;
                    v = ((imul(ah0, bl0)|0) + (r1 >>> 16)|0) + (r0 >>> 16)|0;
                    w = ((imul(al0, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                    m = ((imul(ah0, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                    r0 = (w << 16) | (u & 0xffff);

                    r1 = m;

                    HEAP32[Rk>>2] = r0;
                }

                Rk = (R+(i+j|0))|0;
                HEAP32[Rk>>2] = r1;
            }
    */
        }

        /**
         * Fast squaring
         *
         * Exploits the fact:
         *
         *  X² = ( X0 + X1*B )² = X0² + 2*X0*X1*B + X1²*B²,
         *
         * where B is a power of 2, so:
         *
         *  2*X0*X1*B = (X0*X1 << 1)*B
         *
         * @param A offset of the argument being squared, 32-byte aligned
         * @param lA length of the argument, multiple of 32
         *
         * @param R offset where to place the result to, 32-byte aligned
         */
        function sqr ( A, lA, R ) {
            A  =  A|0;
            lA = lA|0;
            R  =  R|0;

            var al0 = 0, al1 = 0, al2 = 0, al3 = 0, al4 = 0, al5 = 0, al6 = 0, al7 = 0, ah0 = 0, ah1 = 0, ah2 = 0, ah3 = 0, ah4 = 0, ah5 = 0, ah6 = 0, ah7 = 0,
                bl0 = 0, bl1 = 0, bl2 = 0, bl3 = 0, bl4 = 0, bl5 = 0, bl6 = 0, bl7 = 0, bh0 = 0, bh1 = 0, bh2 = 0, bh3 = 0, bh4 = 0, bh5 = 0, bh6 = 0, bh7 = 0,
                r0 = 0, r1 = 0, r2 = 0, r3 = 0, r4 = 0, r5 = 0, r6 = 0, r7 = 0, r8 = 0, r9 = 0, r10 = 0, r11 = 0, r12 = 0, r13 = 0, r14 = 0, r15 = 0,
                u = 0, v = 0, w = 0, c = 0, h = 0, m = 0, r = 0,
                d = 0, dd = 0, p = 0, i = 0, j = 0, k = 0, Ai = 0, Aj = 0, Rk = 0;

            // prepare for iterations
            for ( ; (i|0) < (lA|0); i = (i+4)|0 ) {
                Rk = R+(i<<1)|0;
                ah0 = HEAP32[(A+i)>>2]|0, al0 = ah0 & 0xffff, ah0 = ah0 >>> 16;
                u = imul(al0,al0)|0;
                v = (imul(al0,ah0)|0) + (u >>> 17)|0;
                w = (imul(ah0,ah0)|0) + (v >>> 15)|0;
                HEAP32[(Rk)>>2] = (v << 17) | (u & 0x1ffff);
                HEAP32[(Rk|4)>>2] = w;
            }

            // unrolled 1st iteration
            for ( p = 0; (p|0) < (lA|0); p = (p+8)|0 ) {
                Ai = A+p|0, Rk = R+(p<<1)|0;

                ah0 = HEAP32[(Ai)>>2]|0, al0 = ah0 & 0xffff, ah0 = ah0 >>> 16;

                bh0 = HEAP32[(Ai|4)>>2]|0, bl0 = bh0 & 0xffff, bh0 = bh0 >>> 16;

                u = imul(al0,bl0)|0;
                v = (imul(al0,bh0)|0) + (u >>> 16)|0;
                w = (imul(ah0,bl0)|0) + (v & 0xffff)|0;
                m = ((imul(ah0,bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;

                r = HEAP32[(Rk|4)>>2]|0;
                u = (r & 0xffff) + ((u & 0xffff) << 1)|0;
                w = ((r >>> 16) + ((w & 0xffff) << 1)|0) + (u >>> 16)|0;
                HEAP32[(Rk|4)>>2] = (w << 16) | (u & 0xffff);
                c = w >>> 16;

                r = HEAP32[(Rk|8)>>2]|0;
                u = ((r & 0xffff) + ((m & 0xffff) << 1)|0) + c|0;
                w = ((r >>> 16) + ((m >>> 16) << 1)|0) + (u >>> 16)|0;
                HEAP32[(Rk|8)>>2] = (w << 16) | (u & 0xffff);
                c = w >>> 16;

                if ( c ) {
                    r = HEAP32[(Rk|12)>>2]|0;
                    u = (r & 0xffff) + c|0;
                    w = (r >>> 16) + (u >>> 16)|0;
                    HEAP32[(Rk|12)>>2] = (w << 16) | (u & 0xffff);
                }
            }

            // unrolled 2nd iteration
            for ( p = 0; (p|0) < (lA|0); p = (p+16)|0 ) {
                Ai = A+p|0, Rk = R+(p<<1)|0;

                ah0 = HEAP32[(Ai)>>2]|0, al0 = ah0 & 0xffff, ah0 = ah0 >>> 16,
                ah1 = HEAP32[(Ai|4)>>2]|0, al1 = ah1 & 0xffff, ah1 = ah1 >>> 16;

                bh0 = HEAP32[(Ai|8)>>2]|0, bl0 = bh0 & 0xffff, bh0 = bh0 >>> 16,
                bh1 = HEAP32[(Ai|12)>>2]|0, bl1 = bh1 & 0xffff, bh1 = bh1 >>> 16;

                u = imul(al0, bl0)|0;
                v = imul(ah0, bl0)|0;
                w = ((imul(al0, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah0, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r0 = (w << 16) | (u & 0xffff);

                u = (imul(al0, bl1)|0) + (m & 0xffff)|0;
                v = (imul(ah0, bl1)|0) + (m >>> 16)|0;
                w = ((imul(al0, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah0, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r1 = (w << 16) | (u & 0xffff);

                r2 = m;

                u = (imul(al1, bl0)|0) + (r1 & 0xffff)|0;
                v = (imul(ah1, bl0)|0) + (r1 >>> 16)|0;
                w = ((imul(al1, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah1, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r1 = (w << 16) | (u & 0xffff);

                u = ((imul(al1, bl1)|0) + (r2 & 0xffff)|0) + (m & 0xffff)|0;
                v = ((imul(ah1, bl1)|0) + (r2 >>> 16)|0) + (m >>> 16)|0;
                w = ((imul(al1, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah1, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r2 = (w << 16) | (u & 0xffff);

                r3 = m;

                r = HEAP32[(Rk|8)>>2]|0;
                u = (r & 0xffff) + ((r0 & 0xffff) << 1)|0;
                w = ((r >>> 16) + ((r0 >>> 16) << 1)|0) + (u >>> 16)|0;
                HEAP32[(Rk|8)>>2] = (w << 16) | (u & 0xffff);
                c = w >>> 16;

                r = HEAP32[(Rk|12)>>2]|0;
                u = ((r & 0xffff) + ((r1 & 0xffff) << 1)|0)  + c|0;
                w = ((r >>> 16) + ((r1 >>> 16) << 1)|0) + (u >>> 16)|0;
                HEAP32[(Rk|12)>>2] = (w << 16) | (u & 0xffff);
                c = w >>> 16;

                r = HEAP32[(Rk|16)>>2]|0;
                u = ((r & 0xffff) + ((r2 & 0xffff) << 1)|0) + c|0;
                w = ((r >>> 16) + ((r2 >>> 16) << 1)|0) + (u >>> 16)|0;
                HEAP32[(Rk|16)>>2] = (w << 16) | (u & 0xffff);
                c = w >>> 16;

                r = HEAP32[(Rk|20)>>2]|0;
                u = ((r & 0xffff) + ((r3 & 0xffff) << 1)|0) + c|0;
                w = ((r >>> 16) + ((r3 >>> 16) << 1)|0) + (u >>> 16)|0;
                HEAP32[(Rk|20)>>2] = (w << 16) | (u & 0xffff);
                c = w >>> 16;

                for ( k = 24; !!c & ( (k|0) < 32 ); k = (k+4)|0 ) {
                    r = HEAP32[(Rk|k)>>2]|0;
                    u = (r & 0xffff) + c|0;
                    w = (r >>> 16) + (u >>> 16)|0;
                    HEAP32[(Rk|k)>>2] = (w << 16) | (u & 0xffff);
                    c = w >>> 16;
                }
            }

            // unrolled 3rd iteration
            for ( p = 0; (p|0) < (lA|0); p = (p+32)|0 ) {
                Ai = A+p|0, Rk = R+(p<<1)|0;

                ah0 = HEAP32[(Ai)>>2]|0, al0 = ah0 & 0xffff, ah0 = ah0 >>> 16,
                ah1 = HEAP32[(Ai|4)>>2]|0, al1 = ah1 & 0xffff, ah1 = ah1 >>> 16,
                ah2 = HEAP32[(Ai|8)>>2]|0, al2 = ah2 & 0xffff, ah2 = ah2 >>> 16,
                ah3 = HEAP32[(Ai|12)>>2]|0, al3 = ah3 & 0xffff, ah3 = ah3 >>> 16;

                bh0 = HEAP32[(Ai|16)>>2]|0, bl0 = bh0 & 0xffff, bh0 = bh0 >>> 16,
                bh1 = HEAP32[(Ai|20)>>2]|0, bl1 = bh1 & 0xffff, bh1 = bh1 >>> 16,
                bh2 = HEAP32[(Ai|24)>>2]|0, bl2 = bh2 & 0xffff, bh2 = bh2 >>> 16,
                bh3 = HEAP32[(Ai|28)>>2]|0, bl3 = bh3 & 0xffff, bh3 = bh3 >>> 16;

                u = imul(al0, bl0)|0;
                v = imul(ah0, bl0)|0;
                w = ((imul(al0, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah0, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r0 = (w << 16) | (u & 0xffff);

                u = (imul(al0, bl1)|0) + (m & 0xffff)|0;
                v = (imul(ah0, bl1)|0) + (m >>> 16)|0;
                w = ((imul(al0, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah0, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r1 = (w << 16) | (u & 0xffff);

                u = (imul(al0, bl2)|0) + (m & 0xffff)|0;
                v = (imul(ah0, bl2)|0) + (m >>> 16)|0;
                w = ((imul(al0, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah0, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r2 = (w << 16) | (u & 0xffff);

                u = (imul(al0, bl3)|0) + (m & 0xffff)|0;
                v = (imul(ah0, bl3)|0) + (m >>> 16)|0;
                w = ((imul(al0, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah0, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r3 = (w << 16) | (u & 0xffff);

                r4 = m;

                u = (imul(al1, bl0)|0) + (r1 & 0xffff)|0;
                v = (imul(ah1, bl0)|0) + (r1 >>> 16)|0;
                w = ((imul(al1, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah1, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r1 = (w << 16) | (u & 0xffff);

                u = ((imul(al1, bl1)|0) + (r2 & 0xffff)|0) + (m & 0xffff)|0;
                v = ((imul(ah1, bl1)|0) + (r2 >>> 16)|0) + (m >>> 16)|0;
                w = ((imul(al1, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah1, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r2 = (w << 16) | (u & 0xffff);

                u = ((imul(al1, bl2)|0) + (r3 & 0xffff)|0) + (m & 0xffff)|0;
                v = ((imul(ah1, bl2)|0) + (r3 >>> 16)|0) + (m >>> 16)|0;
                w = ((imul(al1, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah1, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r3 = (w << 16) | (u & 0xffff);

                u = ((imul(al1, bl3)|0) + (r4 & 0xffff)|0) + (m & 0xffff)|0;
                v = ((imul(ah1, bl3)|0) + (r4 >>> 16)|0) + (m >>> 16)|0;
                w = ((imul(al1, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah1, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r4 = (w << 16) | (u & 0xffff);

                r5 = m;

                u = (imul(al2, bl0)|0) + (r2 & 0xffff)|0;
                v = (imul(ah2, bl0)|0) + (r2 >>> 16)|0;
                w = ((imul(al2, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah2, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r2 = (w << 16) | (u & 0xffff);

                u = ((imul(al2, bl1)|0) + (r3 & 0xffff)|0) + (m & 0xffff)|0;
                v = ((imul(ah2, bl1)|0) + (r3 >>> 16)|0) + (m >>> 16)|0;
                w = ((imul(al2, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah2, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r3 = (w << 16) | (u & 0xffff);

                u = ((imul(al2, bl2)|0) + (r4 & 0xffff)|0) + (m & 0xffff)|0;
                v = ((imul(ah2, bl2)|0) + (r4 >>> 16)|0) + (m >>> 16)|0;
                w = ((imul(al2, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah2, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r4 = (w << 16) | (u & 0xffff);

                u = ((imul(al2, bl3)|0) + (r5 & 0xffff)|0) + (m & 0xffff)|0;
                v = ((imul(ah2, bl3)|0) + (r5 >>> 16)|0) + (m >>> 16)|0;
                w = ((imul(al2, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah2, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r5 = (w << 16) | (u & 0xffff);

                r6 = m;

                u = (imul(al3, bl0)|0) + (r3 & 0xffff)|0;
                v = (imul(ah3, bl0)|0) + (r3 >>> 16)|0;
                w = ((imul(al3, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah3, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r3 = (w << 16) | (u & 0xffff);

                u = ((imul(al3, bl1)|0) + (r4 & 0xffff)|0) + (m & 0xffff)|0;
                v = ((imul(ah3, bl1)|0) + (r4 >>> 16)|0) + (m >>> 16)|0;
                w = ((imul(al3, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah3, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r4 = (w << 16) | (u & 0xffff);

                u = ((imul(al3, bl2)|0) + (r5 & 0xffff)|0) + (m & 0xffff)|0;
                v = ((imul(ah3, bl2)|0) + (r5 >>> 16)|0) + (m >>> 16)|0;
                w = ((imul(al3, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah3, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r5 = (w << 16) | (u & 0xffff);

                u = ((imul(al3, bl3)|0) + (r6 & 0xffff)|0) + (m & 0xffff)|0;
                v = ((imul(ah3, bl3)|0) + (r6 >>> 16)|0) + (m >>> 16)|0;
                w = ((imul(al3, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                m = ((imul(ah3, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                r6 = (w << 16) | (u & 0xffff);

                r7 = m;

                r = HEAP32[(Rk|16)>>2]|0;
                u = (r & 0xffff) + ((r0 & 0xffff) << 1)|0;
                w = ((r >>> 16) + ((r0 >>> 16) << 1)|0) + (u >>> 16)|0;
                HEAP32[(Rk|16)>>2] = (w << 16) | (u & 0xffff);
                c = w >>> 16;

                r = HEAP32[(Rk|20)>>2]|0;
                u = ((r & 0xffff) + ((r1 & 0xffff) << 1)|0)  + c|0;
                w = ((r >>> 16) + ((r1 >>> 16) << 1)|0) + (u >>> 16)|0;
                HEAP32[(Rk|20)>>2] = (w << 16) | (u & 0xffff);
                c = w >>> 16;

                r = HEAP32[(Rk|24)>>2]|0;
                u = ((r & 0xffff) + ((r2 & 0xffff) << 1)|0) + c|0;
                w = ((r >>> 16) + ((r2 >>> 16) << 1)|0) + (u >>> 16)|0;
                HEAP32[(Rk|24)>>2] = (w << 16) | (u & 0xffff);
                c = w >>> 16;

                r = HEAP32[(Rk|28)>>2]|0;
                u = ((r & 0xffff) + ((r3 & 0xffff) << 1)|0) + c|0;
                w = ((r >>> 16) + ((r3 >>> 16) << 1)|0) + (u >>> 16)|0;
                HEAP32[(Rk|28)>>2] = (w << 16) | (u & 0xffff);
                c = w >>> 16;

                r = HEAP32[(Rk+32)>>2]|0;
                u = ((r & 0xffff) + ((r4 & 0xffff) << 1)|0) + c|0;
                w = ((r >>> 16) + ((r4 >>> 16) << 1)|0) + (u >>> 16)|0;
                HEAP32[(Rk+32)>>2] = (w << 16) | (u & 0xffff);
                c = w >>> 16;

                r = HEAP32[(Rk+36)>>2]|0;
                u = ((r & 0xffff) + ((r5 & 0xffff) << 1)|0) + c|0;
                w = ((r >>> 16) + ((r5 >>> 16) << 1)|0) + (u >>> 16)|0;
                HEAP32[(Rk+36)>>2] = (w << 16) | (u & 0xffff);
                c = w >>> 16;

                r = HEAP32[(Rk+40)>>2]|0;
                u = ((r & 0xffff) + ((r6 & 0xffff) << 1)|0) + c|0;
                w = ((r >>> 16) + ((r6 >>> 16) << 1)|0) + (u >>> 16)|0;
                HEAP32[(Rk+40)>>2] = (w << 16) | (u & 0xffff);
                c = w >>> 16;

                r = HEAP32[(Rk+44)>>2]|0;
                u = ((r & 0xffff) + ((r7 & 0xffff) << 1)|0) + c|0;
                w = ((r >>> 16) + ((r7 >>> 16) << 1)|0) + (u >>> 16)|0;
                HEAP32[(Rk+44)>>2] = (w << 16) | (u & 0xffff);
                c = w >>> 16;

                for ( k = 48; !!c & ( (k|0) < 64 ); k = (k+4)|0 ) {
                    r = HEAP32[(Rk+k)>>2]|0;
                    u = (r & 0xffff) + c|0;
                    w = (r >>> 16) + (u >>> 16)|0;
                    HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                    c = w >>> 16;
                }
            }

            // perform iterations
            for ( d = 32; (d|0) < (lA|0); d = d << 1 ) { // depth loop
                dd = d << 1;

                for ( p = 0; (p|0) < (lA|0); p = (p+dd)|0 ) { // part loop
                    Rk = R+(p<<1)|0;

                    h = 0;
                    for ( i = 0; (i|0) < (d|0); i = (i+32)|0 ) { // multiply-and-add loop
                        Ai = (A+p|0)+i|0;

                        ah0 = HEAP32[(Ai)>>2]|0, al0 = ah0 & 0xffff, ah0 = ah0 >>> 16,
                        ah1 = HEAP32[(Ai|4)>>2]|0, al1 = ah1 & 0xffff, ah1 = ah1 >>> 16,
                        ah2 = HEAP32[(Ai|8)>>2]|0, al2 = ah2 & 0xffff, ah2 = ah2 >>> 16,
                        ah3 = HEAP32[(Ai|12)>>2]|0, al3 = ah3 & 0xffff, ah3 = ah3 >>> 16,
                        ah4 = HEAP32[(Ai|16)>>2]|0, al4 = ah4 & 0xffff, ah4 = ah4 >>> 16,
                        ah5 = HEAP32[(Ai|20)>>2]|0, al5 = ah5 & 0xffff, ah5 = ah5 >>> 16,
                        ah6 = HEAP32[(Ai|24)>>2]|0, al6 = ah6 & 0xffff, ah6 = ah6 >>> 16,
                        ah7 = HEAP32[(Ai|28)>>2]|0, al7 = ah7 & 0xffff, ah7 = ah7 >>> 16;

                        r8 = r9 = r10 = r11 = r12 = r13 = r14 = r15 = c = 0;

                        for ( j = 0; (j|0) < (d|0); j = (j+32)|0 ) {
                            Aj = ((A+p|0)+d|0)+j|0;

                            bh0 = HEAP32[(Aj)>>2]|0, bl0 = bh0 & 0xffff, bh0 = bh0 >>> 16,
                            bh1 = HEAP32[(Aj|4)>>2]|0, bl1 = bh1 & 0xffff, bh1 = bh1 >>> 16,
                            bh2 = HEAP32[(Aj|8)>>2]|0, bl2 = bh2 & 0xffff, bh2 = bh2 >>> 16,
                            bh3 = HEAP32[(Aj|12)>>2]|0, bl3 = bh3 & 0xffff, bh3 = bh3 >>> 16,
                            bh4 = HEAP32[(Aj|16)>>2]|0, bl4 = bh4 & 0xffff, bh4 = bh4 >>> 16,
                            bh5 = HEAP32[(Aj|20)>>2]|0, bl5 = bh5 & 0xffff, bh5 = bh5 >>> 16,
                            bh6 = HEAP32[(Aj|24)>>2]|0, bl6 = bh6 & 0xffff, bh6 = bh6 >>> 16,
                            bh7 = HEAP32[(Aj|28)>>2]|0, bl7 = bh7 & 0xffff, bh7 = bh7 >>> 16;

                            r0 = r1 = r2 = r3 = r4 = r5 = r6 = r7 = 0;

                            u = ((imul(al0, bl0)|0) + (r0 & 0xffff)|0) + (r8 & 0xffff)|0;
                            v = ((imul(ah0, bl0)|0) + (r0 >>> 16)|0) + (r8 >>> 16)|0;
                            w = ((imul(al0, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah0, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r0 = (w << 16) | (u & 0xffff);

                            u = ((imul(al0, bl1)|0) + (r1 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah0, bl1)|0) + (r1 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al0, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah0, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r1 = (w << 16) | (u & 0xffff);

                            u = ((imul(al0, bl2)|0) + (r2 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah0, bl2)|0) + (r2 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al0, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah0, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r2 = (w << 16) | (u & 0xffff);

                            u = ((imul(al0, bl3)|0) + (r3 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah0, bl3)|0) + (r3 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al0, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah0, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r3 = (w << 16) | (u & 0xffff);

                            u = ((imul(al0, bl4)|0) + (r4 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah0, bl4)|0) + (r4 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al0, bh4)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah0, bh4)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r4 = (w << 16) | (u & 0xffff);

                            u = ((imul(al0, bl5)|0) + (r5 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah0, bl5)|0) + (r5 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al0, bh5)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah0, bh5)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r5 = (w << 16) | (u & 0xffff);

                            u = ((imul(al0, bl6)|0) + (r6 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah0, bl6)|0) + (r6 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al0, bh6)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah0, bh6)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r6 = (w << 16) | (u & 0xffff);

                            u = ((imul(al0, bl7)|0) + (r7 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah0, bl7)|0) + (r7 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al0, bh7)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah0, bh7)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r7 = (w << 16) | (u & 0xffff);

                            r8 = m;

                            u = ((imul(al1, bl0)|0) + (r1 & 0xffff)|0) + (r9 & 0xffff)|0;
                            v = ((imul(ah1, bl0)|0) + (r1 >>> 16)|0) + (r9 >>> 16)|0;
                            w = ((imul(al1, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah1, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r1 = (w << 16) | (u & 0xffff);

                            u = ((imul(al1, bl1)|0) + (r2 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah1, bl1)|0) + (r2 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al1, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah1, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r2 = (w << 16) | (u & 0xffff);

                            u = ((imul(al1, bl2)|0) + (r3 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah1, bl2)|0) + (r3 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al1, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah1, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r3 = (w << 16) | (u & 0xffff);

                            u = ((imul(al1, bl3)|0) + (r4 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah1, bl3)|0) + (r4 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al1, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah1, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r4 = (w << 16) | (u & 0xffff);

                            u = ((imul(al1, bl4)|0) + (r5 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah1, bl4)|0) + (r5 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al1, bh4)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah1, bh4)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r5 = (w << 16) | (u & 0xffff);

                            u = ((imul(al1, bl5)|0) + (r6 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah1, bl5)|0) + (r6 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al1, bh5)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah1, bh5)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r6 = (w << 16) | (u & 0xffff);

                            u = ((imul(al1, bl6)|0) + (r7 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah1, bl6)|0) + (r7 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al1, bh6)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah1, bh6)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r7 = (w << 16) | (u & 0xffff);

                            u = ((imul(al1, bl7)|0) + (r8 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah1, bl7)|0) + (r8 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al1, bh7)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah1, bh7)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r8 = (w << 16) | (u & 0xffff);

                            r9 = m;

                            u = ((imul(al2, bl0)|0) + (r2 & 0xffff)|0) + (r10 & 0xffff)|0;
                            v = ((imul(ah2, bl0)|0) + (r2 >>> 16)|0) + (r10 >>> 16)|0;
                            w = ((imul(al2, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah2, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r2 = (w << 16) | (u & 0xffff);

                            u = ((imul(al2, bl1)|0) + (r3 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah2, bl1)|0) + (r3 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al2, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah2, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r3 = (w << 16) | (u & 0xffff);

                            u = ((imul(al2, bl2)|0) + (r4 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah2, bl2)|0) + (r4 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al2, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah2, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r4 = (w << 16) | (u & 0xffff);

                            u = ((imul(al2, bl3)|0) + (r5 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah2, bl3)|0) + (r5 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al2, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah2, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r5 = (w << 16) | (u & 0xffff);

                            u = ((imul(al2, bl4)|0) + (r6 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah2, bl4)|0) + (r6 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al2, bh4)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah2, bh4)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r6 = (w << 16) | (u & 0xffff);

                            u = ((imul(al2, bl5)|0) + (r7 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah2, bl5)|0) + (r7 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al2, bh5)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah2, bh5)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r7 = (w << 16) | (u & 0xffff);

                            u = ((imul(al2, bl6)|0) + (r8 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah2, bl6)|0) + (r8 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al2, bh6)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah2, bh6)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r8 = (w << 16) | (u & 0xffff);

                            u = ((imul(al2, bl7)|0) + (r9 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah2, bl7)|0) + (r9 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al2, bh7)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah2, bh7)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r9 = (w << 16) | (u & 0xffff);

                            r10 = m;

                            u = ((imul(al3, bl0)|0) + (r3 & 0xffff)|0) + (r11 & 0xffff)|0;
                            v = ((imul(ah3, bl0)|0) + (r3 >>> 16)|0) + (r11 >>> 16)|0;
                            w = ((imul(al3, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah3, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r3 = (w << 16) | (u & 0xffff);

                            u = ((imul(al3, bl1)|0) + (r4 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah3, bl1)|0) + (r4 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al3, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah3, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r4 = (w << 16) | (u & 0xffff);

                            u = ((imul(al3, bl2)|0) + (r5 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah3, bl2)|0) + (r5 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al3, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah3, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r5 = (w << 16) | (u & 0xffff);

                            u = ((imul(al3, bl3)|0) + (r6 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah3, bl3)|0) + (r6 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al3, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah3, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r6 = (w << 16) | (u & 0xffff);

                            u = ((imul(al3, bl4)|0) + (r7 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah3, bl4)|0) + (r7 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al3, bh4)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah3, bh4)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r7 = (w << 16) | (u & 0xffff);

                            u = ((imul(al3, bl5)|0) + (r8 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah3, bl5)|0) + (r8 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al3, bh5)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah3, bh5)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r8 = (w << 16) | (u & 0xffff);

                            u = ((imul(al3, bl6)|0) + (r9 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah3, bl6)|0) + (r9 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al3, bh6)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah3, bh6)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r9 = (w << 16) | (u & 0xffff);

                            u = ((imul(al3, bl7)|0) + (r10 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah3, bl7)|0) + (r10 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al3, bh7)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah3, bh7)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r10 = (w << 16) | (u & 0xffff);

                            r11 = m;

                            u = ((imul(al4, bl0)|0) + (r4 & 0xffff)|0) + (r12 & 0xffff)|0;
                            v = ((imul(ah4, bl0)|0) + (r4 >>> 16)|0) + (r12 >>> 16)|0;
                            w = ((imul(al4, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah4, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r4 = (w << 16) | (u & 0xffff);

                            u = ((imul(al4, bl1)|0) + (r5 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah4, bl1)|0) + (r5 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al4, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah4, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r5 = (w << 16) | (u & 0xffff);

                            u = ((imul(al4, bl2)|0) + (r6 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah4, bl2)|0) + (r6 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al4, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah4, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r6 = (w << 16) | (u & 0xffff);

                            u = ((imul(al4, bl3)|0) + (r7 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah4, bl3)|0) + (r7 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al4, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah4, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r7 = (w << 16) | (u & 0xffff);

                            u = ((imul(al4, bl4)|0) + (r8 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah4, bl4)|0) + (r8 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al4, bh4)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah4, bh4)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r8 = (w << 16) | (u & 0xffff);

                            u = ((imul(al4, bl5)|0) + (r9 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah4, bl5)|0) + (r9 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al4, bh5)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah4, bh5)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r9 = (w << 16) | (u & 0xffff);

                            u = ((imul(al4, bl6)|0) + (r10 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah4, bl6)|0) + (r10 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al4, bh6)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah4, bh6)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r10 = (w << 16) | (u & 0xffff);

                            u = ((imul(al4, bl7)|0) + (r11 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah4, bl7)|0) + (r11 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al4, bh7)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah4, bh7)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r11 = (w << 16) | (u & 0xffff);

                            r12 = m;

                            u = ((imul(al5, bl0)|0) + (r5 & 0xffff)|0) + (r13 & 0xffff)|0;
                            v = ((imul(ah5, bl0)|0) + (r5 >>> 16)|0) + (r13 >>> 16)|0;
                            w = ((imul(al5, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah5, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r5 = (w << 16) | (u & 0xffff);

                            u = ((imul(al5, bl1)|0) + (r6 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah5, bl1)|0) + (r6 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al5, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah5, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r6 = (w << 16) | (u & 0xffff);

                            u = ((imul(al5, bl2)|0) + (r7 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah5, bl2)|0) + (r7 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al5, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah5, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r7 = (w << 16) | (u & 0xffff);

                            u = ((imul(al5, bl3)|0) + (r8 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah5, bl3)|0) + (r8 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al5, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah5, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r8 = (w << 16) | (u & 0xffff);

                            u = ((imul(al5, bl4)|0) + (r9 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah5, bl4)|0) + (r9 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al5, bh4)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah5, bh4)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r9 = (w << 16) | (u & 0xffff);

                            u = ((imul(al5, bl5)|0) + (r10 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah5, bl5)|0) + (r10 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al5, bh5)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah5, bh5)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r10 = (w << 16) | (u & 0xffff);

                            u = ((imul(al5, bl6)|0) + (r11 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah5, bl6)|0) + (r11 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al5, bh6)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah5, bh6)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r11 = (w << 16) | (u & 0xffff);

                            u = ((imul(al5, bl7)|0) + (r12 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah5, bl7)|0) + (r12 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al5, bh7)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah5, bh7)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r12 = (w << 16) | (u & 0xffff);

                            r13 = m;

                            u = ((imul(al6, bl0)|0) + (r6 & 0xffff)|0) + (r14 & 0xffff)|0;
                            v = ((imul(ah6, bl0)|0) + (r6 >>> 16)|0) + (r14 >>> 16)|0;
                            w = ((imul(al6, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah6, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r6 = (w << 16) | (u & 0xffff);

                            u = ((imul(al6, bl1)|0) + (r7 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah6, bl1)|0) + (r7 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al6, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah6, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r7 = (w << 16) | (u & 0xffff);

                            u = ((imul(al6, bl2)|0) + (r8 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah6, bl2)|0) + (r8 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al6, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah6, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r8 = (w << 16) | (u & 0xffff);

                            u = ((imul(al6, bl3)|0) + (r9 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah6, bl3)|0) + (r9 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al6, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah6, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r9 = (w << 16) | (u & 0xffff);

                            u = ((imul(al6, bl4)|0) + (r10 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah6, bl4)|0) + (r10 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al6, bh4)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah6, bh4)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r10 = (w << 16) | (u & 0xffff);

                            u = ((imul(al6, bl5)|0) + (r11 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah6, bl5)|0) + (r11 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al6, bh5)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah6, bh5)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r11 = (w << 16) | (u & 0xffff);

                            u = ((imul(al6, bl6)|0) + (r12 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah6, bl6)|0) + (r12 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al6, bh6)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah6, bh6)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r12 = (w << 16) | (u & 0xffff);

                            u = ((imul(al6, bl7)|0) + (r13 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah6, bl7)|0) + (r13 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al6, bh7)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah6, bh7)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r13 = (w << 16) | (u & 0xffff);

                            r14 = m;

                            u = ((imul(al7, bl0)|0) + (r7 & 0xffff)|0) + (r15 & 0xffff)|0;
                            v = ((imul(ah7, bl0)|0) + (r7 >>> 16)|0) + (r15 >>> 16)|0;
                            w = ((imul(al7, bh0)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah7, bh0)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r7 = (w << 16) | (u & 0xffff);

                            u = ((imul(al7, bl1)|0) + (r8 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah7, bl1)|0) + (r8 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al7, bh1)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah7, bh1)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r8 = (w << 16) | (u & 0xffff);

                            u = ((imul(al7, bl2)|0) + (r9 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah7, bl2)|0) + (r9 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al7, bh2)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah7, bh2)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r9 = (w << 16) | (u & 0xffff);

                            u = ((imul(al7, bl3)|0) + (r10 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah7, bl3)|0) + (r10 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al7, bh3)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah7, bh3)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r10 = (w << 16) | (u & 0xffff);

                            u = ((imul(al7, bl4)|0) + (r11 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah7, bl4)|0) + (r11 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al7, bh4)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah7, bh4)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r11 = (w << 16) | (u & 0xffff);

                            u = ((imul(al7, bl5)|0) + (r12 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah7, bl5)|0) + (r12 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al7, bh5)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah7, bh5)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r12 = (w << 16) | (u & 0xffff);

                            u = ((imul(al7, bl6)|0) + (r13 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah7, bl6)|0) + (r13 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al7, bh6)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah7, bh6)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r13 = (w << 16) | (u & 0xffff);

                            u = ((imul(al7, bl7)|0) + (r14 & 0xffff)|0) + (m & 0xffff)|0;
                            v = ((imul(ah7, bl7)|0) + (r14 >>> 16)|0) + (m >>> 16)|0;
                            w = ((imul(al7, bh7)|0) + (v & 0xffff)|0) + (u >>> 16)|0;
                            m = ((imul(ah7, bh7)|0) + (v >>> 16)|0) + (w >>> 16)|0;
                            r14 = (w << 16) | (u & 0xffff);

                            r15 = m;

                            k = d+(i+j|0)|0;
                            r = HEAP32[(Rk+k)>>2]|0;
                            u = ((r & 0xffff) + ((r0 & 0xffff) << 1)|0) + c|0;
                            w = ((r >>> 16) + ((r0 >>> 16) << 1)|0) + (u >>> 16)|0;
                            HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                            c = w >>> 16;

                            k = k+4|0;
                            r = HEAP32[(Rk+k)>>2]|0;
                            u = ((r & 0xffff) + ((r1 & 0xffff) << 1)|0) + c|0;
                            w = ((r >>> 16) + ((r1 >>> 16) << 1)|0) + (u >>> 16)|0;
                            HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                            c = w >>> 16;

                            k = k+4|0;
                            r = HEAP32[(Rk+k)>>2]|0;
                            u = ((r & 0xffff) + ((r2 & 0xffff) << 1)|0) + c|0;
                            w = ((r >>> 16) + ((r2 >>> 16) << 1)|0) + (u >>> 16)|0;
                            HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                            c = w >>> 16;

                            k = k+4|0;
                            r = HEAP32[(Rk+k)>>2]|0;
                            u = ((r & 0xffff) + ((r3 & 0xffff) << 1)|0) + c|0;
                            w = ((r >>> 16) + ((r3 >>> 16) << 1)|0) + (u >>> 16)|0;
                            HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                            c = w >>> 16;

                            k = k+4|0;
                            r = HEAP32[(Rk+k)>>2]|0;
                            u = ((r & 0xffff) + ((r4 & 0xffff) << 1)|0) + c|0;
                            w = ((r >>> 16) + ((r4 >>> 16) << 1)|0) + (u >>> 16)|0;
                            HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                            c = w >>> 16;

                            k = k+4|0;
                            r = HEAP32[(Rk+k)>>2]|0;
                            u = ((r & 0xffff) + ((r5 & 0xffff) << 1)|0) + c|0;
                            w = ((r >>> 16) + ((r5 >>> 16) << 1)|0) + (u >>> 16)|0;
                            HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                            c = w >>> 16;

                            k = k+4|0;
                            r = HEAP32[(Rk+k)>>2]|0;
                            u = ((r & 0xffff) + ((r6 & 0xffff) << 1)|0) + c|0;
                            w = ((r >>> 16) + ((r6 >>> 16) << 1)|0) + (u >>> 16)|0;
                            HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                            c = w >>> 16;

                            k = k+4|0;
                            r = HEAP32[(Rk+k)>>2]|0;
                            u = ((r & 0xffff) + ((r7 & 0xffff) << 1)|0) + c|0;
                            w = ((r >>> 16) + ((r7 >>> 16) << 1)|0) + (u >>> 16)|0;
                            HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                            c = w >>> 16;
                        }

                        k = d+(i+j|0)|0;
                        r = HEAP32[(Rk+k)>>2]|0;
                        u = (((r & 0xffff) + ((r8 & 0xffff) << 1)|0) + c|0) + h|0;
                        w = ((r >>> 16) + ((r8 >>> 16) << 1)|0) + (u >>> 16)|0;
                        HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                        c = w >>> 16;

                        k = k+4|0;
                        r = HEAP32[(Rk+k)>>2]|0;
                        u = ((r & 0xffff) + ((r9 & 0xffff) << 1)|0) + c|0;
                        w = ((r >>> 16) + ((r9 >>> 16) << 1)|0) + (u >>> 16)|0;
                        HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                        c = w >>> 16;

                        k = k+4|0;
                        r = HEAP32[(Rk+k)>>2]|0;
                        u = ((r & 0xffff) + ((r10 & 0xffff) << 1)|0) + c|0;
                        w = ((r >>> 16) + ((r10 >>> 16) << 1)|0) + (u >>> 16)|0;
                        HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                        c = w >>> 16;

                        k = k+4|0;
                        r = HEAP32[(Rk+k)>>2]|0;
                        u = ((r & 0xffff) + ((r11 & 0xffff) << 1)|0) + c|0;
                        w = ((r >>> 16) + ((r11 >>> 16) << 1)|0) + (u >>> 16)|0;
                        HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                        c = w >>> 16;

                        k = k+4|0;
                        r = HEAP32[(Rk+k)>>2]|0;
                        u = ((r & 0xffff) + ((r12 & 0xffff) << 1)|0) + c|0;
                        w = ((r >>> 16) + ((r12 >>> 16) << 1)|0) + (u >>> 16)|0;
                        HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                        c = w >>> 16;

                        k = k+4|0;
                        r = HEAP32[(Rk+k)>>2]|0;
                        u = ((r & 0xffff) + ((r13 & 0xffff) << 1)|0) + c|0;
                        w = ((r >>> 16) + ((r13 >>> 16) << 1)|0) + (u >>> 16)|0;
                        HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                        c = w >>> 16;

                        k = k+4|0;
                        r = HEAP32[(Rk+k)>>2]|0;
                        u = ((r & 0xffff) + ((r14 & 0xffff) << 1)|0) + c|0;
                        w = ((r >>> 16) + ((r14 >>> 16) << 1)|0) + (u >>> 16)|0;
                        HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                        c = w >>> 16;

                        k = k+4|0;
                        r = HEAP32[(Rk+k)>>2]|0;
                        u = ((r & 0xffff) + ((r15 & 0xffff) << 1)|0) + c|0;
                        w = ((r >>> 16) + ((r15 >>> 16) << 1)|0) + (u >>> 16)|0;
                        HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                        h = w >>> 16;
                    }

                    for ( k = k+4|0; !!h & ( (k|0) < (dd<<1) ); k = (k+4)|0 ) { // carry propagation loop
                        r = HEAP32[(Rk+k)>>2]|0;
                        u = (r & 0xffff) + h|0;
                        w = (r >>> 16) + (u >>> 16)|0;
                        HEAP32[(Rk+k)>>2] = (w << 16) | (u & 0xffff);
                        h = w >>> 16;
                    }
                }
            }
        }

        /**
         * Conventional division
         *
         * @param A offset of the numerator, 32-byte aligned
         * @param lA length of the numerator, multiple of 32
         *
         * @param B offset of the divisor, 32-byte aligned
         * @param lB length of the divisor, multiple of 32
         *
         * @param R offset where to place the remainder to, 32-byte aligned
         *
         * @param Q offser where to place the quotient to, 32-byte aligned
         */

        function div ( N, lN, D, lD, Q ) {
            N  =  N|0;
            lN = lN|0;
            D  =  D|0;
            lD = lD|0;
            Q  =  Q|0;

            var n = 0, d = 0, e = 0,
                u1 = 0, u0 = 0,
                v0 = 0, vh = 0, vl = 0,
                qh = 0, ql = 0, rh = 0, rl = 0,
                t1 = 0, t2 = 0, m = 0, c = 0,
                i = 0, j = 0, k = 0;

            // number of significant limbs in `N` (multiplied by 4)
            for ( i = (lN-1) & -4; (i|0) >= 0; i = (i-4)|0 ) {
                n = HEAP32[(N+i)>>2]|0;
                if ( n ) {
                    lN = i;
                    break;
                }
            }

            // number of significant limbs in `D` (multiplied by 4)
            for ( i = (lD-1) & -4; (i|0) >= 0; i = (i-4)|0 ) {
                d = HEAP32[(D+i)>>2]|0;
                if ( d ) {
                    lD = i;
                    break;
                }
            }

            // `D` is zero? WTF?!

            // calculate `e` — the power of 2 of the normalization factor
            while ( (d & 0x80000000) == 0 ) {
                d = d << 1;
                e = e + 1|0;
            }

            // normalize `N` in place
            u0 = HEAP32[(N+lN)>>2]|0;
            if ( e ) {
                u1 = u0>>>(32-e|0);
                for ( i = (lN-4)|0; (i|0) >= 0; i = (i-4)|0 ) {
                    n = HEAP32[(N+i)>>2]|0;
                    HEAP32[(N+i+4)>>2] = (u0 << e) | ( e ? n >>> (32-e|0) : 0 );
                    u0 = n;
                }
                HEAP32[N>>2] = u0 << e;
            }

            // normalize `D` in place
            if ( e ) {
                v0 = HEAP32[(D+lD)>>2]|0;
                for ( i = (lD-4)|0; (i|0) >= 0; i = (i-4)|0 ) {
                    d = HEAP32[(D+i)>>2]|0;
                    HEAP32[(D+i+4)>>2] = (v0 << e) | ( d >>> (32-e|0) );
                    v0 = d;
                }
                HEAP32[D>>2] = v0 << e;
            }

            // divisor parts won't change
            v0 = HEAP32[(D+lD)>>2]|0;
            vh = v0 >>> 16, vl = v0 & 0xffff;

            // perform division
            for ( i = lN; (i|0) >= (lD|0); i = (i-4)|0 ) {
                j = (i-lD)|0;

                // estimate high part of the quotient
                u0 = HEAP32[(N+i)>>2]|0;
                qh = ( (u1>>>0) / (vh>>>0) )|0, rh = ( (u1>>>0) % (vh>>>0) )|0, t1 = imul(qh, vl)|0;
                while ( ( (qh|0) == 0x10000 ) | ( (t1>>>0) > (((rh << 16)|(u0 >>> 16))>>>0) ) ) {
                    qh = (qh-1)|0, rh = (rh+vh)|0, t1 = (t1-vl)|0;
                    if ( (rh|0) >= 0x10000 ) break;
                }

                // bulk multiply-and-subtract
                // m - multiplication carry, c - subtraction carry
                m = 0, c = 0;
                for ( k = 0; (k|0) <= (lD|0); k = (k+4)|0 ) {
                    d = HEAP32[(D+k)>>2]|0;
                    t1 = (imul(qh, d & 0xffff)|0) + (m >>> 16)|0;
                    t2 = (imul(qh, d >>> 16)|0) + (t1 >>> 16)|0;
                    d = (m & 0xffff) | (t1 << 16);
                    m = t2;
                    n = HEAP32[(N+j+k)>>2]|0;
                    t1 = ((n & 0xffff) - (d & 0xffff)|0) + c|0;
                    t2 = ((n >>> 16) - (d >>> 16)|0) + (t1 >> 16)|0;
                    HEAP32[(N+j+k)>>2] = (t2 << 16) | (t1 & 0xffff);
                    c = t2 >> 16;
                }
                t1 = ((u1 & 0xffff) - (m & 0xffff)|0) + c|0;
                t2 = ((u1 >>> 16) - (m >>> 16)|0) + (t1 >> 16)|0;
                u1 = (t2 << 16) | (t1 & 0xffff);
                c = t2 >> 16;

                // add `D` back if got carry-out
                if ( c ) {
                    qh = (qh-1)|0;
                    c = 0;
                    for ( k = 0; (k|0) <= (lD|0); k = (k+4)|0 ) {
                        d = HEAP32[(D+k)>>2]|0;
                        n = HEAP32[(N+j+k)>>2]|0;
                        t1 = (n & 0xffff) + c|0;
                        t2 = (n >>> 16) + d + (t1 >>> 16)|0;
                        HEAP32[(N+j+k)>>2] = (t2 << 16) | (t1 & 0xffff);
                        c = t2 >>> 16;
                    }
                    u1 = (u1+c)|0;
                }

                // estimate low part of the quotient
                u0 = HEAP32[(N+i)>>2]|0;
                n = (u1 << 16) | (u0 >>> 16);
                ql = ( (n>>>0) / (vh>>>0) )|0, rl = ( (n>>>0) % (vh>>>0) )|0, t1 = imul(ql, vl)|0;
                while ( ( (ql|0) == 0x10000 ) | ( (t1>>>0) > (((rl << 16)|(u0 & 0xffff))>>>0) ) ) {
                    ql = (ql-1)|0, rl = (rl+vh)|0, t1 = (t1-vl)|0;
                    if ( (rl|0) >= 0x10000 ) break;
                }

                // bulk multiply-and-subtract
                // m - multiplication carry, c - subtraction carry
                m = 0, c = 0;
                for ( k = 0; (k|0) <= (lD|0); k = (k+4)|0 ) {
                    d = HEAP32[(D+k)>>2]|0;
                    t1 = (imul(ql, d & 0xffff)|0) + (m & 0xffff)|0;
                    t2 = ((imul(ql, d >>> 16)|0) + (t1 >>> 16)|0) + (m >>> 16)|0;
                    d = (t1 & 0xffff) | (t2 << 16);
                    m = t2 >>> 16;
                    n = HEAP32[(N+j+k)>>2]|0;
                    t1 = ((n & 0xffff) - (d & 0xffff)|0) + c|0;
                    t2 = ((n >>> 16) - (d >>> 16)|0) + (t1 >> 16)|0;
                    c = t2 >> 16;
                    HEAP32[(N+j+k)>>2] = (t2 << 16) | (t1 & 0xffff);
                }
                t1 = ((u1 & 0xffff) - (m & 0xffff)|0) + c|0;
                t2 = ((u1 >>> 16) - (m >>> 16)|0) + (t1 >> 16)|0;
                c = t2 >> 16;

                // add `D` back if got carry-out
                if ( c ) {
                    ql = (ql-1)|0;
                    c = 0;
                    for ( k = 0; (k|0) <= (lD|0); k = (k+4)|0 ) {
                        d = HEAP32[(D+k)>>2]|0;
                        n = HEAP32[(N+j+k)>>2]|0;
                        t1 = ((n & 0xffff) + (d & 0xffff)|0) + c|0;
                        t2 = ((n >>> 16) + (d >>> 16)|0) + (t1 >>> 16)|0;
                        c = t2 >>> 16;
                        HEAP32[(N+j+k)>>2] = (t1 & 0xffff) | (t2 << 16);
                    }
                }

                // got quotient limb
                HEAP32[(Q+j)>>2] = (qh << 16) | ql;

                u1 = HEAP32[(N+i)>>2]|0;
            }

            if ( e ) {
                // TODO denormalize `D` in place

                // denormalize `N` in place
                u0 = HEAP32[N>>2]|0;
                for ( i = 4; (i|0) <= (lD|0); i = (i+4)|0 ) {
                    n = HEAP32[(N+i)>>2]|0;
                    HEAP32[(N+i-4)>>2] = ( n << (32-e|0) ) | (u0 >>> e);
                    u0 = n;
                }
                HEAP32[(N+lD)>>2] = u0 >>> e;
            }
        }

        /**
         * Montgomery modular reduction
         *
         * Definition:
         *
         *  MREDC(A) = A × X (mod N),
         *  M × X = N × Y + 1,
         *
         * where M = 2^(32*m) such that N < M and A < N×M
         *
         * Numbers `X` and `Y` can be calculated using Extended Euclidean Algorithm.
         */
        function mredc ( A, lA, N, lN, y, R ) {
            A  =  A|0;
            lA = lA|0;
            N  =  N|0;
            lN = lN|0;
            y  =  y|0;
            R  =  R|0;

            var T = 0,
                c = 0, uh = 0, ul = 0, vl = 0, vh = 0, w0 = 0, w1 = 0, w2 = 0, r0 = 0, r1 = 0,
                i = 0, j = 0, k = 0;

            T = salloc(lN<<1)|0;
            z(lN<<1, 0, T);

            cp( lA, A, T );

            // HAC 14.32
            for ( i = 0; (i|0) < (lN|0); i = (i+4)|0 ) {
                uh = HEAP32[(T+i)>>2]|0, ul = uh & 0xffff, uh = uh >>> 16;
                vh = y >>> 16, vl = y & 0xffff;
                w0 = imul(ul,vl)|0, w1 = ( (imul(ul,vh)|0) + (imul(uh,vl)|0) | 0 ) + (w0 >>> 16) | 0;
                ul = w0 & 0xffff, uh = w1 & 0xffff;
                r1 = 0;
                for ( j = 0; (j|0) < (lN|0); j = (j+4)|0 ) {
                    k = (i+j)|0;
                    vh = HEAP32[(N+j)>>2]|0, vl = vh & 0xffff, vh = vh >>> 16;
                    r0 = HEAP32[(T+k)>>2]|0;
                    w0 = ((imul(ul, vl)|0) + (r1 & 0xffff)|0) + (r0 & 0xffff)|0;
                    w1 = ((imul(ul, vh)|0) + (r1 >>> 16)|0) + (r0 >>> 16)|0;
                    w2 = ((imul(uh, vl)|0) + (w1 & 0xffff)|0) + (w0 >>> 16)|0;
                    r1 = ((imul(uh, vh)|0) + (w2 >>> 16)|0) + (w1 >>> 16)|0;
                    r0 = (w2 << 16) | (w0 & 0xffff);
                    HEAP32[(T+k)>>2] = r0;
                }
                k = (i+j)|0;
                r0 = HEAP32[(T+k)>>2]|0;
                w0 = ((r0 & 0xffff) + (r1 & 0xffff)|0) + c|0;
                w1 = ((r0 >>> 16) + (r1 >>> 16)|0) + (w0 >>> 16)|0;
                HEAP32[(T+k)>>2] = (w1 << 16) | (w0 & 0xffff);
                c = w1 >>> 16;
            }

            cp( lN, (T+lN)|0, R );

            sfree(lN<<1);

            if ( c | ( (cmp( N, lN, R, lN )|0) <= 0 ) ) {
                sub( R, lN, N, lN, R, lN )|0;
            }
        }

        return {
            sreset: sreset,
            salloc: salloc,
            sfree:  sfree,
            z: z,
            tst: tst,
            neg: neg,
            cmp: cmp,
            add: add,
            sub: sub,
            mul: mul,
            sqr: sqr,
            div: div,
            mredc: mredc
        };
    };

    function Number_extGCD(a, b) {
        var sa = a < 0 ? -1 : 1, sb = b < 0 ? -1 : 1, xi = 1, xj = 0, yi = 0, yj = 1, r, q, t, a_cmp_b;
        a *= sa;
        b *= sb;
        a_cmp_b = a < b;
        if (a_cmp_b) {
            t = a;
            (a = b), (b = t);
            t = sa;
            sa = sb;
            sb = t;
        }
        (q = Math.floor(a / b)), (r = a - q * b);
        while (r) {
            (t = xi - q * xj), (xi = xj), (xj = t);
            (t = yi - q * yj), (yi = yj), (yj = t);
            (a = b), (b = r);
            (q = Math.floor(a / b)), (r = a - q * b);
        }
        xj *= sa;
        yj *= sb;
        if (a_cmp_b) {
            t = xj;
            (xj = yj), (yj = t);
        }
        return {
            gcd: b,
            x: xj,
            y: yj,
        };
    }
    function BigNumber_extGCD(a, b) {
        let sa = a.sign;
        let sb = b.sign;
        if (sa < 0)
            a = a.negate();
        if (sb < 0)
            b = b.negate();
        const a_cmp_b = a.compare(b);
        if (a_cmp_b < 0) {
            let t = a;
            (a = b), (b = t);
            let t2 = sa;
            sa = sb;
            sb = t2;
        }
        var xi = BigNumber.ONE, xj = BigNumber.ZERO, lx = b.bitLength, yi = BigNumber.ZERO, yj = BigNumber.ONE, ly = a.bitLength, z, r, q;
        z = a.divide(b);
        while ((r = z.remainder) !== BigNumber.ZERO) {
            q = z.quotient;
            (z = xi.subtract(q.multiply(xj).clamp(lx)).clamp(lx)), (xi = xj), (xj = z);
            (z = yi.subtract(q.multiply(yj).clamp(ly)).clamp(ly)), (yi = yj), (yj = z);
            (a = b), (b = r);
            z = a.divide(b);
        }
        if (sa < 0)
            xj = xj.negate();
        if (sb < 0)
            yj = yj.negate();
        if (a_cmp_b < 0) {
            let t = xj;
            (xj = yj), (yj = t);
        }
        return {
            gcd: b,
            x: xj,
            y: yj,
        };
    }

    function getRandomValues(buf) {
        if (typeof process !== 'undefined') {
            const nodeCrypto = require('crypto');
            const bytes = nodeCrypto.randomBytes(buf.length);
            buf.set(bytes);
            return;
        }
        if (window.crypto && window.crypto.getRandomValues) {
            window.crypto.getRandomValues(buf);
            return;
        }
        if (self.crypto && self.crypto.getRandomValues) {
            self.crypto.getRandomValues(buf);
            return;
        }
        // @ts-ignore
        if (window.msCrypto && window.msCrypto.getRandomValues) {
            // @ts-ignore
            window.msCrypto.getRandomValues(buf);
            return;
        }
        throw new Error('No secure random number generator available.');
    }

    ///////////////////////////////////////////////////////////////////////////////
    const _bigint_stdlib = { Uint32Array: Uint32Array, Math: Math };
    const _bigint_heap = new Uint32Array(0x100000);
    let _bigint_asm;
    function _half_imul(a, b) {
        return (a * b) | 0;
    }
    if (_bigint_stdlib.Math.imul === undefined) {
        _bigint_stdlib.Math.imul = _half_imul;
        _bigint_asm = bigint_asm(_bigint_stdlib, null, _bigint_heap.buffer);
        delete _bigint_stdlib.Math.imul;
    }
    else {
        _bigint_asm = bigint_asm(_bigint_stdlib, null, _bigint_heap.buffer);
    }
    ///////////////////////////////////////////////////////////////////////////////
    const _BigNumber_ZERO_limbs = new Uint32Array(0);
    class BigNumber {
        constructor(num) {
            let limbs = _BigNumber_ZERO_limbs;
            let bitlen = 0;
            let sign = 0;
            if (num === undefined) ;
            else {
                for (var i = 0; !num[i]; i++)
                    ;
                bitlen = (num.length - i) * 8;
                if (!bitlen)
                    return BigNumber.ZERO;
                limbs = new Uint32Array((bitlen + 31) >> 5);
                for (var j = num.length - 4; j >= i; j -= 4) {
                    limbs[(num.length - 4 - j) >> 2] = (num[j] << 24) | (num[j + 1] << 16) | (num[j + 2] << 8) | num[j + 3];
                }
                if (i - j === 3) {
                    limbs[limbs.length - 1] = num[i];
                }
                else if (i - j === 2) {
                    limbs[limbs.length - 1] = (num[i] << 8) | num[i + 1];
                }
                else if (i - j === 1) {
                    limbs[limbs.length - 1] = (num[i] << 16) | (num[i + 1] << 8) | num[i + 2];
                }
                sign = 1;
            }
            this.limbs = limbs;
            this.bitLength = bitlen;
            this.sign = sign;
        }
        static fromString(str) {
            const bytes = string_to_bytes(str);
            return new BigNumber(bytes);
        }
        static fromNumber(num) {
            let limbs = _BigNumber_ZERO_limbs;
            let bitlen = 0;
            let sign = 0;
            var absnum = Math.abs(num);
            if (absnum > 0xffffffff) {
                limbs = new Uint32Array(2);
                limbs[0] = absnum | 0;
                limbs[1] = (absnum / 0x100000000) | 0;
                bitlen = 52;
            }
            else if (absnum > 0) {
                limbs = new Uint32Array(1);
                limbs[0] = absnum;
                bitlen = 32;
            }
            else {
                limbs = _BigNumber_ZERO_limbs;
                bitlen = 0;
            }
            sign = num < 0 ? -1 : 1;
            return BigNumber.fromConfig({ limbs, bitLength: bitlen, sign });
        }
        static fromArrayBuffer(buffer) {
            return new BigNumber(new Uint8Array(buffer));
        }
        static fromConfig(obj) {
            const bn = new BigNumber();
            bn.limbs = new Uint32Array(obj.limbs);
            bn.bitLength = obj.bitLength;
            bn.sign = obj.sign;
            return bn;
        }
        toString(radix) {
            radix = radix || 16;
            const limbs = this.limbs;
            const bitlen = this.bitLength;
            let str = '';
            if (radix === 16) {
                // FIXME clamp last limb to (bitlen % 32)
                for (var i = ((bitlen + 31) >> 5) - 1; i >= 0; i--) {
                    var h = limbs[i].toString(16);
                    str += '00000000'.substr(h.length);
                    str += h;
                }
                str = str.replace(/^0+/, '');
                if (!str.length)
                    str = '0';
            }
            else {
                throw new IllegalArgumentError('bad radix');
            }
            if (this.sign < 0)
                str = '-' + str;
            return str;
        }
        toBytes() {
            const bitlen = this.bitLength;
            const limbs = this.limbs;
            if (bitlen === 0)
                return new Uint8Array(0);
            const bytelen = (bitlen + 7) >> 3;
            const bytes = new Uint8Array(bytelen);
            for (let i = 0; i < bytelen; i++) {
                let j = bytelen - i - 1;
                bytes[i] = limbs[j >> 2] >> ((j & 3) << 3);
            }
            return bytes;
        }
        /**
         * Downgrade to Number
         */
        valueOf() {
            const limbs = this.limbs;
            const bits = this.bitLength;
            const sign = this.sign;
            if (!sign)
                return 0;
            if (bits <= 32)
                return sign * (limbs[0] >>> 0);
            if (bits <= 52)
                return sign * (0x100000000 * (limbs[1] >>> 0) + (limbs[0] >>> 0));
            // normalization
            let i, l, e = 0;
            for (i = limbs.length - 1; i >= 0; i--) {
                if ((l = limbs[i]) === 0)
                    continue;
                while (((l << e) & 0x80000000) === 0)
                    e++;
                break;
            }
            if (i === 0)
                return sign * (limbs[0] >>> 0);
            return (sign *
                (0x100000 * (((limbs[i] << e) | (e ? limbs[i - 1] >>> (32 - e) : 0)) >>> 0) +
                    (((limbs[i - 1] << e) | (e && i > 1 ? limbs[i - 2] >>> (32 - e) : 0)) >>> 12)) *
                Math.pow(2, 32 * i - e - 52));
        }
        clamp(b) {
            const limbs = this.limbs;
            const bitlen = this.bitLength;
            // FIXME check b is number and in a valid range
            if (b >= bitlen)
                return this;
            const clamped = new BigNumber();
            let n = (b + 31) >> 5;
            let k = b % 32;
            clamped.limbs = new Uint32Array(limbs.subarray(0, n));
            clamped.bitLength = b;
            clamped.sign = this.sign;
            if (k)
                clamped.limbs[n - 1] &= -1 >>> (32 - k);
            return clamped;
        }
        slice(f, b) {
            const limbs = this.limbs;
            const bitlen = this.bitLength;
            if (f < 0)
                throw new RangeError('TODO');
            if (f >= bitlen)
                return BigNumber.ZERO;
            if (b === undefined || b > bitlen - f)
                b = bitlen - f;
            const sliced = new BigNumber();
            let n = f >> 5;
            let m = (f + b + 31) >> 5;
            let l = (b + 31) >> 5;
            let t = f % 32;
            let k = b % 32;
            const slimbs = new Uint32Array(l);
            if (t) {
                for (var i = 0; i < m - n - 1; i++) {
                    slimbs[i] = (limbs[n + i] >>> t) | (limbs[n + i + 1] << (32 - t));
                }
                slimbs[i] = limbs[n + i] >>> t;
            }
            else {
                slimbs.set(limbs.subarray(n, m));
            }
            if (k) {
                slimbs[l - 1] &= -1 >>> (32 - k);
            }
            sliced.limbs = slimbs;
            sliced.bitLength = b;
            sliced.sign = this.sign;
            return sliced;
        }
        negate() {
            const negative = new BigNumber();
            negative.limbs = this.limbs;
            negative.bitLength = this.bitLength;
            negative.sign = -1 * this.sign;
            return negative;
        }
        compare(that) {
            var alimbs = this.limbs, alimbcnt = alimbs.length, blimbs = that.limbs, blimbcnt = blimbs.length, z = 0;
            if (this.sign < that.sign)
                return -1;
            if (this.sign > that.sign)
                return 1;
            _bigint_heap.set(alimbs, 0);
            _bigint_heap.set(blimbs, alimbcnt);
            z = _bigint_asm.cmp(0, alimbcnt << 2, alimbcnt << 2, blimbcnt << 2);
            return z * this.sign;
        }
        add(that) {
            if (!this.sign)
                return that;
            if (!that.sign)
                return this;
            var abitlen = this.bitLength, alimbs = this.limbs, alimbcnt = alimbs.length, asign = this.sign, bbitlen = that.bitLength, blimbs = that.limbs, blimbcnt = blimbs.length, bsign = that.sign, rbitlen, rlimbcnt, rsign, rof, result = new BigNumber();
            rbitlen = (abitlen > bbitlen ? abitlen : bbitlen) + (asign * bsign > 0 ? 1 : 0);
            rlimbcnt = (rbitlen + 31) >> 5;
            _bigint_asm.sreset();
            var pA = _bigint_asm.salloc(alimbcnt << 2), pB = _bigint_asm.salloc(blimbcnt << 2), pR = _bigint_asm.salloc(rlimbcnt << 2);
            _bigint_asm.z(pR - pA + (rlimbcnt << 2), 0, pA);
            _bigint_heap.set(alimbs, pA >> 2);
            _bigint_heap.set(blimbs, pB >> 2);
            if (asign * bsign > 0) {
                _bigint_asm.add(pA, alimbcnt << 2, pB, blimbcnt << 2, pR, rlimbcnt << 2);
                rsign = asign;
            }
            else if (asign > bsign) {
                rof = _bigint_asm.sub(pA, alimbcnt << 2, pB, blimbcnt << 2, pR, rlimbcnt << 2);
                rsign = rof ? bsign : asign;
            }
            else {
                rof = _bigint_asm.sub(pB, blimbcnt << 2, pA, alimbcnt << 2, pR, rlimbcnt << 2);
                rsign = rof ? asign : bsign;
            }
            if (rof)
                _bigint_asm.neg(pR, rlimbcnt << 2, pR, rlimbcnt << 2);
            if (_bigint_asm.tst(pR, rlimbcnt << 2) === 0)
                return BigNumber.ZERO;
            result.limbs = new Uint32Array(_bigint_heap.subarray(pR >> 2, (pR >> 2) + rlimbcnt));
            result.bitLength = rbitlen;
            result.sign = rsign;
            return result;
        }
        subtract(that) {
            return this.add(that.negate());
        }
        square() {
            if (!this.sign)
                return BigNumber.ZERO;
            var abitlen = this.bitLength, alimbs = this.limbs, alimbcnt = alimbs.length, rbitlen, rlimbcnt, result = new BigNumber();
            rbitlen = abitlen << 1;
            rlimbcnt = (rbitlen + 31) >> 5;
            _bigint_asm.sreset();
            var pA = _bigint_asm.salloc(alimbcnt << 2), pR = _bigint_asm.salloc(rlimbcnt << 2);
            _bigint_asm.z(pR - pA + (rlimbcnt << 2), 0, pA);
            _bigint_heap.set(alimbs, pA >> 2);
            _bigint_asm.sqr(pA, alimbcnt << 2, pR);
            result.limbs = new Uint32Array(_bigint_heap.subarray(pR >> 2, (pR >> 2) + rlimbcnt));
            result.bitLength = rbitlen;
            result.sign = 1;
            return result;
        }
        divide(that) {
            var abitlen = this.bitLength, alimbs = this.limbs, alimbcnt = alimbs.length, bbitlen = that.bitLength, blimbs = that.limbs, blimbcnt = blimbs.length, qlimbcnt, rlimbcnt, quotient = BigNumber.ZERO, remainder = BigNumber.ZERO;
            _bigint_asm.sreset();
            var pA = _bigint_asm.salloc(alimbcnt << 2), pB = _bigint_asm.salloc(blimbcnt << 2), pQ = _bigint_asm.salloc(alimbcnt << 2);
            _bigint_asm.z(pQ - pA + (alimbcnt << 2), 0, pA);
            _bigint_heap.set(alimbs, pA >> 2);
            _bigint_heap.set(blimbs, pB >> 2);
            _bigint_asm.div(pA, alimbcnt << 2, pB, blimbcnt << 2, pQ);
            qlimbcnt = _bigint_asm.tst(pQ, alimbcnt << 2) >> 2;
            if (qlimbcnt) {
                quotient = new BigNumber();
                quotient.limbs = new Uint32Array(_bigint_heap.subarray(pQ >> 2, (pQ >> 2) + qlimbcnt));
                quotient.bitLength = abitlen < qlimbcnt << 5 ? abitlen : qlimbcnt << 5;
                quotient.sign = this.sign * that.sign;
            }
            rlimbcnt = _bigint_asm.tst(pA, blimbcnt << 2) >> 2;
            if (rlimbcnt) {
                remainder = new BigNumber();
                remainder.limbs = new Uint32Array(_bigint_heap.subarray(pA >> 2, (pA >> 2) + rlimbcnt));
                remainder.bitLength = bbitlen < rlimbcnt << 5 ? bbitlen : rlimbcnt << 5;
                remainder.sign = this.sign;
            }
            return {
                quotient: quotient,
                remainder: remainder,
            };
        }
        multiply(that) {
            if (!this.sign || !that.sign)
                return BigNumber.ZERO;
            var abitlen = this.bitLength, alimbs = this.limbs, alimbcnt = alimbs.length, bbitlen = that.bitLength, blimbs = that.limbs, blimbcnt = blimbs.length, rbitlen, rlimbcnt, result = new BigNumber();
            rbitlen = abitlen + bbitlen;
            rlimbcnt = (rbitlen + 31) >> 5;
            _bigint_asm.sreset();
            var pA = _bigint_asm.salloc(alimbcnt << 2), pB = _bigint_asm.salloc(blimbcnt << 2), pR = _bigint_asm.salloc(rlimbcnt << 2);
            _bigint_asm.z(pR - pA + (rlimbcnt << 2), 0, pA);
            _bigint_heap.set(alimbs, pA >> 2);
            _bigint_heap.set(blimbs, pB >> 2);
            _bigint_asm.mul(pA, alimbcnt << 2, pB, blimbcnt << 2, pR, rlimbcnt << 2);
            result.limbs = new Uint32Array(_bigint_heap.subarray(pR >> 2, (pR >> 2) + rlimbcnt));
            result.sign = this.sign * that.sign;
            result.bitLength = rbitlen;
            return result;
        }
        isMillerRabinProbablePrime(rounds) {
            var t = BigNumber.fromConfig(this), s = 0;
            t.limbs[0] -= 1;
            while (t.limbs[s >> 5] === 0)
                s += 32;
            while (((t.limbs[s >> 5] >> (s & 31)) & 1) === 0)
                s++;
            t = t.slice(s);
            var m = new Modulus(this), m1 = this.subtract(BigNumber.ONE), a = BigNumber.fromConfig(this), l = this.limbs.length - 1;
            while (a.limbs[l] === 0)
                l--;
            while (--rounds >= 0) {
                getRandomValues(a.limbs);
                if (a.limbs[0] < 2)
                    a.limbs[0] += 2;
                while (a.compare(m1) >= 0)
                    a.limbs[l] >>>= 1;
                var x = m.power(a, t);
                if (x.compare(BigNumber.ONE) === 0)
                    continue;
                if (x.compare(m1) === 0)
                    continue;
                var c = s;
                while (--c > 0) {
                    x = x.square().divide(m).remainder;
                    if (x.compare(BigNumber.ONE) === 0)
                        return false;
                    if (x.compare(m1) === 0)
                        break;
                }
                if (c === 0)
                    return false;
            }
            return true;
        }
        isProbablePrime(paranoia = 80) {
            var limbs = this.limbs;
            var i = 0;
            // Oddity test
            // (50% false positive probability)
            if ((limbs[0] & 1) === 0)
                return false;
            if (paranoia <= 1)
                return true;
            // Magic divisors (3, 5, 17) test
            // (~25% false positive probability)
            var s3 = 0, s5 = 0, s17 = 0;
            for (i = 0; i < limbs.length; i++) {
                var l3 = limbs[i];
                while (l3) {
                    s3 += l3 & 3;
                    l3 >>>= 2;
                }
                var l5 = limbs[i];
                while (l5) {
                    s5 += l5 & 3;
                    l5 >>>= 2;
                    s5 -= l5 & 3;
                    l5 >>>= 2;
                }
                var l17 = limbs[i];
                while (l17) {
                    s17 += l17 & 15;
                    l17 >>>= 4;
                    s17 -= l17 & 15;
                    l17 >>>= 4;
                }
            }
            if (!(s3 % 3) || !(s5 % 5) || !(s17 % 17))
                return false;
            if (paranoia <= 2)
                return true;
            // Miller-Rabin test
            // (≤ 4^(-k) false positive probability)
            return this.isMillerRabinProbablePrime(paranoia >>> 1);
        }
    }
    BigNumber.extGCD = BigNumber_extGCD;
    BigNumber.ZERO = BigNumber.fromNumber(0);
    BigNumber.ONE = BigNumber.fromNumber(1);
    class Modulus extends BigNumber {
        constructor(number) {
            super();
            this.limbs = number.limbs;
            this.bitLength = number.bitLength;
            this.sign = number.sign;
            if (this.valueOf() < 1)
                throw new RangeError();
            if (this.bitLength <= 32)
                return;
            let comodulus;
            if (this.limbs[0] & 1) {
                const bitlen = ((this.bitLength + 31) & -32) + 1;
                const limbs = new Uint32Array((bitlen + 31) >> 5);
                limbs[limbs.length - 1] = 1;
                comodulus = new BigNumber();
                comodulus.sign = 1;
                comodulus.bitLength = bitlen;
                comodulus.limbs = limbs;
                const k = Number_extGCD(0x100000000, this.limbs[0]).y;
                this.coefficient = k < 0 ? -k : 0x100000000 - k;
            }
            else {
                /**
                 * TODO even modulus reduction
                 * Modulus represented as `N = 2^U * V`, where `V` is odd and thus `GCD(2^U, V) = 1`.
                 * Calculation `A = TR' mod V` is made as for odd modulo using Montgomery method.
                 * Calculation `B = TR' mod 2^U` is easy as modulus is a power of 2.
                 * Using Chinese Remainder Theorem and Garner's Algorithm restore `TR' mod N` from `A` and `B`.
                 */
                return;
            }
            this.comodulus = comodulus;
            this.comodulusRemainder = comodulus.divide(this).remainder;
            this.comodulusRemainderSquare = comodulus.square().divide(this).remainder;
        }
        /**
         * Modular reduction
         */
        reduce(a) {
            if (a.bitLength <= 32 && this.bitLength <= 32)
                return BigNumber.fromNumber(a.valueOf() % this.valueOf());
            if (a.compare(this) < 0)
                return a;
            return a.divide(this).remainder;
        }
        /**
         * Modular inverse
         */
        inverse(a) {
            a = this.reduce(a);
            const r = BigNumber_extGCD(this, a);
            if (r.gcd.valueOf() !== 1)
                throw new Error('GCD is not 1');
            if (r.y.sign < 0)
                return r.y.add(this).clamp(this.bitLength);
            return r.y;
        }
        /**
         * Modular exponentiation
         */
        power(g, e) {
            // count exponent set bits
            let c = 0;
            for (let i = 0; i < e.limbs.length; i++) {
                let t = e.limbs[i];
                while (t) {
                    if (t & 1)
                        c++;
                    t >>>= 1;
                }
            }
            // window size parameter
            let k = 8;
            if (e.bitLength <= 4536)
                k = 7;
            if (e.bitLength <= 1736)
                k = 6;
            if (e.bitLength <= 630)
                k = 5;
            if (e.bitLength <= 210)
                k = 4;
            if (e.bitLength <= 60)
                k = 3;
            if (e.bitLength <= 12)
                k = 2;
            if (c <= 1 << (k - 1))
                k = 1;
            // montgomerize base
            g = Modulus._Montgomery_reduce(this.reduce(g).multiply(this.comodulusRemainderSquare), this);
            // precompute odd powers
            const g2 = Modulus._Montgomery_reduce(g.square(), this), gn = new Array(1 << (k - 1));
            gn[0] = g;
            gn[1] = Modulus._Montgomery_reduce(g.multiply(g2), this);
            for (let i = 2; i < 1 << (k - 1); i++) {
                gn[i] = Modulus._Montgomery_reduce(gn[i - 1].multiply(g2), this);
            }
            // perform exponentiation
            const u = this.comodulusRemainder;
            let r = u;
            for (let i = e.limbs.length - 1; i >= 0; i--) {
                let t = e.limbs[i];
                for (let j = 32; j > 0;) {
                    if (t & 0x80000000) {
                        let n = t >>> (32 - k), l = k;
                        while ((n & 1) === 0) {
                            n >>>= 1;
                            l--;
                        }
                        var m = gn[n >>> 1];
                        while (n) {
                            n >>>= 1;
                            if (r !== u)
                                r = Modulus._Montgomery_reduce(r.square(), this);
                        }
                        r = r !== u ? Modulus._Montgomery_reduce(r.multiply(m), this) : m;
                        (t <<= l), (j -= l);
                    }
                    else {
                        if (r !== u)
                            r = Modulus._Montgomery_reduce(r.square(), this);
                        (t <<= 1), j--;
                    }
                }
            }
            // de-montgomerize result
            return Modulus._Montgomery_reduce(r, this);
        }
        static _Montgomery_reduce(a, n) {
            const alimbs = a.limbs;
            const alimbcnt = alimbs.length;
            const nlimbs = n.limbs;
            const nlimbcnt = nlimbs.length;
            const y = n.coefficient;
            _bigint_asm.sreset();
            const pA = _bigint_asm.salloc(alimbcnt << 2), pN = _bigint_asm.salloc(nlimbcnt << 2), pR = _bigint_asm.salloc(nlimbcnt << 2);
            _bigint_asm.z(pR - pA + (nlimbcnt << 2), 0, pA);
            _bigint_heap.set(alimbs, pA >> 2);
            _bigint_heap.set(nlimbs, pN >> 2);
            _bigint_asm.mredc(pA, alimbcnt << 2, pN, nlimbcnt << 2, y, pR);
            const result = new BigNumber();
            result.limbs = new Uint32Array(_bigint_heap.subarray(pR >> 2, (pR >> 2) + nlimbcnt));
            result.bitLength = n.bitLength;
            result.sign = 1;
            return result;
        }
    }

    var _a;
    const rsaAlgorithmName = "RSASSA-PKCS1-v1_5";
    const CBC_IV_LENGTH = 16;
    const GCM_IV_LENGTH = 12;
    const ECC_PUB_KEY_LENGTH = 65;
    let socket = null;
    let workerPool = null;
    const base64ToBytes = (data) => {
        return Uint8Array.from(atob(data), c => c.charCodeAt(0));
    };
    const browserPlatform = (_a = class {
            static normal64Bytes(source) {
                return base64ToBytes(normal64(source));
            }
            static getRandomBytes(length) {
                let data = new Uint8Array(length);
                crypto.getRandomValues(data);
                return data;
            }
            static bytesToBase64(data) {
                const chunkSize = 0x10000;
                if (data.length <= chunkSize) {
                    // @ts-ignore
                    return btoa(String.fromCharCode(...data));
                }
                let chunks = '';
                for (let i = 0; i < data.length; i = i + chunkSize) {
                    // @ts-ignore
                    chunks = chunks + String.fromCharCode(...data.slice(i, i + chunkSize));
                }
                return btoa(chunks);
            }
            static bytesToString(data) {
                return new TextDecoder().decode(data);
            }
            static stringToBytes(data) {
                return new TextEncoder().encode(data);
            }
            static wrapPassword(password) {
                return KeyWrapper.create(password);
                // TODO const wrappedPassword = await crypto.subtle.importKey("raw", password.asBytes(), "PBKDF2", false, ["deriveBits"]);
                // return KeyWrapper.create(wrappedPassword)
            }
            static unWrapPassword(password) {
                return password.getKey();
            }
            static async importKey(keyId, key, storage, canExport) {
                // An AES key for one of our Keeper objects can be used for either CBC or GCM operations.
                // Since CryptoKeys are bound to a particular algorithm, we need to keep a copy for each.
                const extractable = !!canExport;
                const cbcKey = await this.aesCbcImportKey(key, extractable);
                const gcmKey = await this.aesGcmImportKey(key, extractable);
                cryptoKeysCache['cbc'][keyId] = cbcKey;
                cryptoKeysCache['gcm'][keyId] = gcmKey;
                if (storage) {
                    if (storage.saveObject) {
                        await storage.saveObject(this.getStorageKeyId(keyId, 'cbc'), cbcKey);
                        await storage.saveObject(this.getStorageKeyId(keyId, 'gcm'), gcmKey);
                    }
                    else {
                        await storage.saveKeyBytes(keyId, key);
                    }
                }
            }
            static async importKeyEC(keyId, privateKey, publicKey, storage) {
                const key = await this.importPrivateKeyEC(privateKey, publicKey);
                cryptoKeysCache['ecc'][keyId] = key;
                if (storage) {
                    if (storage.saveObject) {
                        await storage.saveObject(this.getStorageKeyId(keyId, 'ecc'), key);
                    }
                    else {
                        const jwk = await crypto.subtle.exportKey('jwk', key);
                        const keyBytes = this.stringToBytes(JSON.stringify(jwk));
                        await storage.saveKeyBytes(keyId, keyBytes);
                    }
                }
            }
            static async importKeyRSA(keyId, key, storage) {
                keyBytesCache[keyId] = key;
                if (storage) {
                    await storage.saveKeyBytes(keyId, key);
                }
            }
            static unloadKeys() {
                cryptoKeysCache.cbc = {};
                cryptoKeysCache.gcm = {};
                cryptoKeysCache.ecc = {};
                keyBytesCache = {};
            }
            static unloadNonUserKeys() {
                cryptoKeysCache = {
                    cbc: {
                        data: cryptoKeysCache.cbc.data
                    },
                    gcm: {
                        data: cryptoKeysCache.gcm.data
                    },
                    ecc: {
                        pk_ecc: cryptoKeysCache.ecc.pk_ecc
                    },
                };
                keyBytesCache = {
                    pk_rsa: keyBytesCache.pk_rsa
                };
            }
            static getStorageKeyId(keyId, keyType) {
                switch (keyType) {
                    case 'cbc':
                    case 'gcm':
                        return `${keyId}_${keyType}`;
                    default:
                        return keyId;
                }
            }
            static async loadCryptoKey(keyId, keyType, storage) {
                if (storage === null || storage === void 0 ? void 0 : storage.getObject) {
                    const storageKeyId = this.getStorageKeyId(keyId, keyType);
                    const storedKey = await storage.getObject(storageKeyId);
                    if (!storedKey) {
                        throw new Error('Unable to load crypto key ' + keyId);
                    }
                    return storedKey;
                }
                const keyBytes = await this.loadKeyBytes(keyId, storage);
                switch (keyType) {
                    case 'cbc':
                        return this.aesCbcImportKey(keyBytes, true);
                    case 'gcm':
                        return this.aesGcmImportKey(keyBytes, true);
                    case 'ecc':
                        const jwk = JSON.parse(this.bytesToString(keyBytes));
                        return this.importECCJsonWebKey(jwk);
                    default:
                        throw new Error('Unsupported keyType: ' + keyType);
                }
            }
            static async loadKeyBytes(keyId, storage) {
                const cachedKey = keyBytesCache[keyId];
                if (cachedKey) {
                    return cachedKey;
                }
                const keyBytes = storage
                    ? await storage.getKeyBytes(keyId)
                    : undefined;
                if (!keyBytes) {
                    throw new Error(`Unable to load the key ${keyId}`);
                }
                keyBytesCache[keyId] = keyBytes;
                return keyBytes;
            }
            static async loadKey(keyId, keyType, storage) {
                const cachedKey = cryptoKeysCache[keyType][keyId];
                if (cachedKey) {
                    return cachedKey;
                }
                const key = await this.loadCryptoKey(keyId, keyType, storage);
                cryptoKeysCache[keyType][keyId] = key;
                return key;
            }
            static async unwrapKeys(keys, storage) {
                if (workerPool) {
                    try {
                        const unwrappedKeys = await workerPool.runTasks(Object.values(keys));
                        // Import keys
                        await Promise.all(Object.entries(unwrappedKeys).map(async ([keyId, keyBytes]) => {
                            try {
                                const { unwrappedType } = keys[keyId];
                                switch (unwrappedType) {
                                    case 'aes':
                                        await this.importKey(keyId, keyBytes, storage, true);
                                        break;
                                    case 'rsa':
                                        await this.importKeyRSA(keyId, keyBytes, storage);
                                        break;
                                    case 'ecc':
                                        try {
                                            const privkey = keyBytes.slice(ECC_PUB_KEY_LENGTH);
                                            const pubKey = keyBytes.slice(0, ECC_PUB_KEY_LENGTH);
                                            await this.importKeyEC(keyId, privkey, pubKey, storage);
                                        }
                                        catch (e) {
                                            console.error('ecc error in unwrapKeys: ', e);
                                        }
                                        break;
                                    default:
                                        throw new Error(`unable to import ${unwrappedType} key`);
                                }
                            }
                            catch (e) {
                                console.error(`Import key error: ${e}`);
                            }
                        }));
                        return; // no error, exit
                    }
                    catch (e) {
                        console.error(`Crypto worker failed: ${e}`);
                        await (workerPool === null || workerPool === void 0 ? void 0 : workerPool.close());
                        workerPool = null;
                    }
                }
                // Default to main thread decryption
                await Promise.all(Object.values(keys).map(async (task) => {
                    const { data, dataId, keyId, encryptionType, unwrappedType } = task;
                    try {
                        await this.unwrapKey(data, dataId, keyId, encryptionType, unwrappedType, storage, true);
                    }
                    catch (e) {
                        if (e instanceof Error && e.message === 'sync_aborted')
                            throw e;
                        console.error(`The key ${dataId} cannot be decrypted (${e.message})`);
                    }
                }));
            }
            static async unwrapKey(key, keyId, unwrappingKeyId, encryptionType, unwrappedKeyType, storage, canExport) {
                switch (unwrappedKeyType) {
                    case 'rsa':
                        if (keyBytesCache[keyId]) {
                            // Skip redundant RSA key decryption
                            return;
                        }
                        await this.unwrapRSAKey(key, keyId, unwrappingKeyId, encryptionType, storage);
                        break;
                    case 'aes':
                        if (cryptoKeysCache['gcm'][keyId]) {
                            // Keeperapp sometimes provides redundant key data, for example, like if you own a record in a shared folder,
                            // or if a record belongs to multiple shared folders. So, short circuit when possible for a performance improvement
                            return;
                        }
                        await this.unwrapAesKey(key, keyId, unwrappingKeyId, encryptionType, storage, canExport);
                        break;
                    // TODO: add something like this, need to find pub/priv key pair
                    case 'ecc':
                        if (cryptoKeysCache['gcm'][keyId]) {
                            return;
                        }
                        try {
                            const privkey = key.slice(ECC_PUB_KEY_LENGTH);
                            const pubKey = key.slice(0, ECC_PUB_KEY_LENGTH);
                            await this.unwrapECCKey(privkey, pubKey, keyId, unwrappingKeyId, encryptionType, storage);
                        }
                        catch (e) {
                            console.error('ecc error in unwrapKey: ', e);
                        }
                        break;
                    default:
                        throw new Error('Unable to unwrap key type ' + unwrappedKeyType);
                }
            }
            static async unwrapAesKey(key, keyId, unwrappingKeyId, encryptionType, storage, canExport) {
                let unwrappingKey;
                let wrappedKey;
                let algoParams;
                switch (encryptionType) {
                    case 'rsa':
                        const rsaKey = await this.loadKeyBytes(unwrappingKeyId, storage);
                        const keyBytes = this.privateDecrypt(key, rsaKey);
                        await this.importKey(keyId, keyBytes, storage, canExport);
                        return;
                    case 'cbc':
                        wrappedKey = key.subarray(CBC_IV_LENGTH);
                        algoParams = {
                            iv: key.subarray(0, CBC_IV_LENGTH),
                            name: 'AES-CBC'
                        };
                        unwrappingKey = await this.loadKey(unwrappingKeyId, encryptionType, storage);
                        break;
                    case 'gcm':
                        wrappedKey = key.subarray(GCM_IV_LENGTH);
                        algoParams = {
                            iv: key.subarray(0, GCM_IV_LENGTH),
                            name: 'AES-GCM'
                        };
                        unwrappingKey = await this.loadKey(unwrappingKeyId, encryptionType, storage);
                        break;
                    case 'ecc':
                        const message = key.slice(ECC_PUB_KEY_LENGTH);
                        wrappedKey = message.subarray(GCM_IV_LENGTH);
                        algoParams = {
                            iv: message.subarray(0, GCM_IV_LENGTH),
                            name: 'AES-GCM'
                        };
                        const ephemeralPublicKey = key.slice(0, ECC_PUB_KEY_LENGTH);
                        const eccPrivateKey = await this.loadKey(unwrappingKeyId, 'ecc', storage);
                        unwrappingKey = await this.deriveSharedSecretKey(ephemeralPublicKey, eccPrivateKey);
                        break;
                }
                const canExtract = (storage === null || storage === void 0 ? void 0 : storage.saveObject) ? !!canExport : true;
                const keyUsages = ['encrypt', 'decrypt', 'unwrapKey', 'wrapKey'];
                const gcmKey = await crypto.subtle.unwrapKey('raw', wrappedKey, unwrappingKey, algoParams, 'AES-GCM', canExtract, keyUsages);
                const cbcKey = await crypto.subtle.unwrapKey('raw', wrappedKey, unwrappingKey, algoParams, 'AES-CBC', canExtract, keyUsages);
                cryptoKeysCache['cbc'][keyId] = cbcKey;
                cryptoKeysCache['gcm'][keyId] = gcmKey;
                if (storage) {
                    if (storage.saveObject) {
                        await storage.saveObject(this.getStorageKeyId(keyId, 'cbc'), cbcKey);
                        await storage.saveObject(this.getStorageKeyId(keyId, 'gcm'), gcmKey);
                    }
                    else {
                        const keyBuffer = await crypto.subtle.exportKey('raw', gcmKey);
                        await storage.saveKeyBytes(keyId, new Uint8Array(keyBuffer));
                    }
                }
            }
            static async unwrapRSAKey(key, keyId, unwrappingKeyId, encryptionType, storage) {
                const rsaKey = await this.decrypt(key, unwrappingKeyId, encryptionType, storage);
                await this.importKeyRSA(keyId, rsaKey, storage);
            }
            // keyId: string, privateKey: Uint8Array, publicKey: Uint8Array, storage?: KeyStorage
            static async unwrapECCKey(privateKey, publicKey, keyId, unwrappingKeyId, encryptionType, storage) {
                const decryptedPrivateKey = await this.decrypt(privateKey, unwrappingKeyId, encryptionType, storage);
                await this.importKeyEC(keyId, decryptedPrivateKey, publicKey, storage);
            }
            static async decrypt(data, keyId, encryptionType, storage) {
                switch (encryptionType) {
                    case 'cbc': {
                        const key = await this.loadKey(keyId, encryptionType, storage);
                        return this.aesCbcDecryptWebCrypto(data, key);
                    }
                    case 'gcm': {
                        const key = await this.loadKey(keyId, encryptionType, storage);
                        return this.aesGcmDecryptWebCrypto(data, key);
                    }
                    case 'rsa': {
                        const key = await this.loadKeyBytes(keyId, storage);
                        return this.privateDecrypt(data, key);
                    }
                    case 'ecc': {
                        // explains ec privkey
                        const key = await this.loadKey(keyId, encryptionType, storage);
                        return this.privateDecryptECWebCrypto(data, key);
                    }
                    default:
                        throw Error('Unknown encryption type: ' + encryptionType);
                }
            }
            static async generateRSAKeyPair() {
                let keyPair = await crypto.subtle.generateKey({
                    name: rsaAlgorithmName,
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                    hash: { name: 'SHA-256' },
                }, true, ["sign", "verify"]);
                let jwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
                let rsaKey = new RSAKey();
                rsaKey.setPrivateEx(base64ToHex(normal64(jwk.n)), base64ToHex(normal64(jwk.e)), base64ToHex(normal64(jwk.d)), base64ToHex(normal64(jwk.p)), base64ToHex(normal64(jwk.q)), base64ToHex(normal64(jwk.dp)), base64ToHex(normal64(jwk.dq)), base64ToHex(normal64(jwk.qi)));
                let public_key = rsaKey.toASN1HexString(false);
                let private_key = rsaKey.toASN1HexString(true);
                return {
                    privateKey: hexToBytes(private_key),
                    publicKey: hexToBytes(public_key),
                };
            }
            static async generateECKeyPair() {
                const ecdh = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
                const privateKey = await crypto.subtle.exportKey('jwk', ecdh.privateKey);
                const publicKey = await crypto.subtle.exportKey('raw', ecdh.publicKey);
                return { publicKey: new Uint8Array(publicKey), privateKey: normal64Bytes(privateKey.d) };
            }
            static async publicEncryptECWithHKDF(message, pubKey, id) {
                const messageBytes = typeof message === "string" ? this.stringToBytes(message) : message;
                return await this.mainPublicEncryptEC(messageBytes, pubKey, id, true);
            }
            static publicEncrypt(data, key) {
                let publicKeyHex = base64ToHex(key);
                const pos = _asnhex_getPosArrayOfChildren_AtObj(publicKeyHex, 0);
                const hN = _asnhex_getHexOfV_AtObj(publicKeyHex, pos[0]);
                const hE = _asnhex_getHexOfV_AtObj(publicKeyHex, pos[1]);
                const rsa = new RSAKey();
                rsa.setPublic(hN, hE);
                const hexBytes = bytesToHex(data);
                const encryptedBinary = rsa.encryptBinary(hexBytes);
                return hexToBytes(encryptedBinary);
            }
            static async mainPublicEncryptEC(data, key, id, useHKDF) {
                const ephemeralKeyPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
                const ephemeralPublicKey = await crypto.subtle.exportKey('raw', ephemeralKeyPair.publicKey);
                const recipientPublicKey = await crypto.subtle.importKey('raw', key, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
                const sharedSecret = await crypto.subtle.deriveBits({ name: 'ECDH', public: recipientPublicKey }, ephemeralKeyPair.privateKey, 256);
                const idBytes = id || new Uint8Array();
                let symmetricKey;
                if (!useHKDF) {
                    const sharedSecretCombined = new Uint8Array(sharedSecret.byteLength + idBytes.byteLength);
                    sharedSecretCombined.set(new Uint8Array(sharedSecret), 0);
                    sharedSecretCombined.set(idBytes, sharedSecret.byteLength);
                    symmetricKey = await crypto.subtle.digest('SHA-256', sharedSecretCombined);
                }
                else {
                    const hkdfKey = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveBits']);
                    symmetricKey = await crypto.subtle.deriveBits({
                        name: 'HKDF',
                        hash: 'SHA-256',
                        salt: new Uint8Array(),
                        info: id
                    }, hkdfKey, 256);
                }
                const cipherText = await this.aesGcmEncrypt(data, new Uint8Array(symmetricKey));
                const result = new Uint8Array(ephemeralPublicKey.byteLength + cipherText.byteLength);
                result.set(new Uint8Array(ephemeralPublicKey), 0);
                result.set(new Uint8Array(cipherText), ephemeralPublicKey.byteLength);
                return result;
            }
            static async publicEncryptEC(data, key, id) {
                return await this.mainPublicEncryptEC(data, key, id);
            }
            static privateDecrypt(data, key) {
                let pkh = bytesToHex(key);
                const rsa = new RSAKey();
                rsa.setPrivateKeyFromASN1HexString(pkh);
                const hexBytes = bytesToHex(data);
                const decryptedBinary = rsa.decryptBinary(hexBytes);
                return hexToBytes(decryptedBinary);
            }
            static async privateDecryptEC(data, privateKey, publicKey, id, useHKDF) {
                if (!publicKey) {
                    throw Error('Public key is required for EC decryption');
                }
                const privateKeyImport = await this.importPrivateKeyEC(privateKey, publicKey);
                return this.privateDecryptECWebCrypto(data, privateKeyImport, id, useHKDF);
            }
            static async importPrivateKeyEC(privateKey, publicKey) {
                const x = webSafe64FromBytes(publicKey.subarray(1, 33));
                const y = webSafe64FromBytes(publicKey.subarray(33, 65));
                const d = webSafe64FromBytes(privateKey);
                const jwk = {
                    'crv': 'P-256',
                    d,
                    'ext': true,
                    'key_ops': [
                        'deriveBits'
                    ],
                    'kty': 'EC',
                    x,
                    y
                };
                return this.importECCJsonWebKey(jwk);
            }
            static async importECCJsonWebKey(jwk) {
                return await crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
            }
            static async deriveSharedSecretKey(ephemeralPublicKey, privateKey, id, useHKDF) {
                var _a;
                const pubCryptoKey = await crypto.subtle.importKey('raw', ephemeralPublicKey, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
                const sharedSecret = await crypto.subtle.deriveBits({ name: 'ECDH', public: pubCryptoKey }, privateKey, 256);
                if (!useHKDF) {
                    let sharedSecretCombined = new Uint8Array(sharedSecret.byteLength + ((_a = id === null || id === void 0 ? void 0 : id.byteLength) !== null && _a !== void 0 ? _a : 0));
                    sharedSecretCombined.set(new Uint8Array(sharedSecret), 0);
                    if (id) {
                        sharedSecretCombined.set(id, sharedSecret.byteLength);
                    }
                    const symmetricKeyBuffer = await crypto.subtle.digest('SHA-256', sharedSecretCombined);
                    return this.aesGcmImportKey(new Uint8Array(symmetricKeyBuffer), false);
                }
                else {
                    const hkdfKey = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveBits']);
                    const symmetricKeyBuffer = await crypto.subtle.deriveBits({
                        name: 'HKDF',
                        hash: 'SHA-256',
                        salt: new Uint8Array(),
                        info: id !== null && id !== void 0 ? id : new Uint8Array()
                    }, hkdfKey, 256);
                    return this.aesGcmImportKey(new Uint8Array(symmetricKeyBuffer), false);
                }
            }
            static async privateDecryptECWebCrypto(data, privateKey, id, useHKDF) {
                const message = data.slice(ECC_PUB_KEY_LENGTH);
                const ephemeralPublicKey = data.slice(0, ECC_PUB_KEY_LENGTH);
                const symmetricKey = await this.deriveSharedSecretKey(ephemeralPublicKey, privateKey, id, useHKDF);
                return await this.aesGcmDecryptWebCrypto(message, symmetricKey);
            }
            static async privateSign(data, key) {
                let _key = await crypto.subtle.importKey("pkcs8", browserPlatform.base64ToBytes(key), "RSA-PSS", true, ["sign"]);
                let signature = await crypto.subtle.sign(rsaAlgorithmName, _key, data);
                return new Uint8Array(signature);
            }
            static async encrypt(data, keyId, encryptionType, storage) {
                switch (encryptionType) {
                    case 'cbc': {
                        const key = await this.loadKey(keyId, encryptionType, storage);
                        return this.aesCbcEncryptWebCrypto(data, key);
                    }
                    case 'gcm': {
                        const key = await this.loadKey(keyId, encryptionType, storage);
                        return this.aesGcmEncryptWebCrypto(data, key);
                    }
                    case 'ecc': {
                        const publicKey = await this.loadKeyBytes(keyId + '_pub');
                        return this.publicEncryptEC(data, publicKey);
                    }
                    case 'rsa': {
                        const publicKey = await this.loadKeyBytes(keyId + '_pub');
                        return this.publicEncrypt(data, this.bytesToBase64(publicKey));
                    }
                    default:
                        throw Error('Unknown encryption type: ' + encryptionType);
                }
            }
            static async wrapKey(keyId, wrappingKeyId, encryptionType, storage) {
                switch (encryptionType) {
                    case 'cbc':
                    case 'gcm':
                        return this.aesWrapKey(keyId, wrappingKeyId, encryptionType, storage);
                    default:
                        throw new Error(`Unsupported encryptionType (${encryptionType})`);
                }
            }
            static async aesWrapKey(keyId, wrappingKeyId, encryptionType, storage) {
                const key = await this.loadKey(keyId, 'cbc', storage);
                const wrappingKey = await this.loadKey(wrappingKeyId, encryptionType, storage);
                let algoParams;
                let iv;
                switch (encryptionType) {
                    case 'cbc':
                        iv = this.getRandomBytes(CBC_IV_LENGTH);
                        algoParams = {
                            iv,
                            name: 'AES-CBC'
                        };
                        break;
                    case 'gcm':
                        iv = this.getRandomBytes(GCM_IV_LENGTH);
                        algoParams = {
                            iv,
                            name: 'AES-GCM'
                        };
                        break;
                }
                const wrappedKey = await crypto.subtle.wrapKey('raw', key, wrappingKey, algoParams);
                let resArr = new Uint8Array(wrappedKey);
                let result = new Uint8Array(iv.length + resArr.length);
                result.set(iv);
                result.set(resArr, iv.length);
                return result;
            }
            static async aesGcmEncrypt(data, key) {
                let _key = await crypto.subtle.importKey("raw", key, "AES-GCM", true, ["encrypt"]);
                return this.aesGcmEncryptWebCrypto(data, _key);
            }
            static async aesGcmEncryptWebCrypto(data, key) {
                let iv = browserPlatform.getRandomBytes(GCM_IV_LENGTH);
                let res = await crypto.subtle.encrypt({
                    name: "AES-GCM",
                    iv: iv
                }, key, data);
                let resArr = new Uint8Array(res);
                let result = new Uint8Array(iv.length + resArr.length);
                result.set(iv);
                result.set(resArr, iv.length);
                return result;
            }
            static async aesGcmDecrypt(data, key) {
                const _key = await this.aesGcmImportKey(key, false);
                return this.aesGcmDecryptWebCrypto(data, _key);
            }
            static async aesGcmImportKey(keyBytes, extractable) {
                return crypto.subtle.importKey("raw", keyBytes, "AES-GCM", extractable, ['decrypt', 'encrypt', 'unwrapKey', 'wrapKey']);
            }
            static async aesGcmDecryptWebCrypto(data, key) {
                const iv = data.subarray(0, GCM_IV_LENGTH);
                const encrypted = data.subarray(GCM_IV_LENGTH);
                const res = await crypto.subtle.decrypt({
                    name: "AES-GCM",
                    iv: iv
                }, key, encrypted);
                return new Uint8Array(res);
            }
            static async aesCbcEncryptWebCrypto(data, key) {
                let iv = browserPlatform.getRandomBytes(CBC_IV_LENGTH);
                let res = await crypto.subtle.encrypt({
                    name: "aes-cbc",
                    iv: iv
                }, key, data);
                let resArr = new Uint8Array(res);
                let result = new Uint8Array(iv.byteLength + resArr.byteLength);
                result.set(iv);
                result.set(resArr, iv.byteLength);
                return result;
            }
            // The browser's implementation of aes cbc only works when padding is required. 
            // Use asmCrypto for no padding. crypto-js was found to have a vulnerability (Cache-Timing attack)
            static async aesCbcEncrypt(data, key, usePadding) {
                if (usePadding) {
                    let _key = await crypto.subtle.importKey("raw", key, "aes-cbc", true, ["encrypt"]);
                    return this.aesCbcEncryptWebCrypto(data, _key);
                }
                else {
                    const iv = browserPlatform.getRandomBytes(CBC_IV_LENGTH);
                    const encrBytes = AES_CBC.encrypt(data, key, false, iv);
                    const keeperformat = new Uint8Array(iv.length + encrBytes.length);
                    keeperformat.set(iv);
                    keeperformat.set(encrBytes, iv.length);
                    return keeperformat;
                }
            }
            // The browser's implementation of aes cbc only works when padding is required. 
            // Use asmCrypto for no padding. crypto-js was found to have a vulnerability (Cache-Timing attack)
            static async aesCbcDecrypt(data, key, usePadding) {
                if (usePadding) {
                    let _key = await this.aesCbcImportKey(key, false);
                    return this.aesCbcDecryptWebCrypto(data, _key);
                }
                else {
                    var iv = data.subarray(0, CBC_IV_LENGTH);
                    var ciphertext = data.subarray(CBC_IV_LENGTH);
                    var result = AES_CBC.decrypt(ciphertext, key, false, iv);
                    return result;
                }
            }
            static async aesCbcImportKey(keyBytes, extractable) {
                return crypto.subtle.importKey('raw', keyBytes, 'AES-CBC', extractable, ['decrypt', 'encrypt', 'unwrapKey', 'wrapKey']);
            }
            static async aesCbcDecryptWebCrypto(data, key) {
                const iv = data.subarray(0, CBC_IV_LENGTH);
                const ciphertext = data.subarray(CBC_IV_LENGTH);
                const decrypt = await crypto.subtle.decrypt({
                    name: 'AES-CBC',
                    iv: iv
                }, key, ciphertext);
                return new Uint8Array(decrypt);
            }
            static async deriveKey(password, saltBytes, iterations) {
                let key = await crypto.subtle.importKey("raw", password.getKey(), "PBKDF2", false, ["deriveBits"]);
                let derived = await crypto.subtle.deriveBits({
                    name: "PBKDF2",
                    salt: saltBytes,
                    iterations: iterations,
                    hash: {
                        name: "SHA-256"
                    }
                }, key, 256);
                return new Uint8Array(derived);
            }
            static async deriveKeyV2(domain, password, saltBytes, iterations) {
                let key = await crypto.subtle.importKey("raw", Uint8Array.of(...browserPlatform.stringToBytes(domain), ...browserPlatform.unWrapPassword(password)), "PBKDF2", false, ["deriveBits"]);
                let derived = await crypto.subtle.deriveBits({
                    name: "PBKDF2",
                    salt: saltBytes,
                    iterations: iterations,
                    hash: {
                        name: "SHA-512"
                    }
                }, key, 512);
                let hmacKey = await crypto.subtle.importKey("raw", derived, {
                    name: "HMAC",
                    hash: {
                        name: "SHA-256"
                    }
                }, false, ["sign", "verify"]);
                const reduced = await crypto.subtle.sign("HMAC", hmacKey, browserPlatform.stringToBytes(domain));
                return new Uint8Array(reduced);
            }
            static async calcAuthVerifier(key) {
                let digest = await crypto.subtle.digest("SHA-256", key);
                return new Uint8Array(digest);
            }
            static async get(url, headers) {
                let resp = await fetch(url, {
                    method: "GET",
                    headers: Object.entries(headers),
                });
                let body = await resp.arrayBuffer();
                return {
                    statusCode: resp.status,
                    headers: resp.headers,
                    data: new Uint8Array(body)
                };
            }
            static async post(url, request, headers) {
                let resp = await fetch(url, {
                    method: "POST",
                    headers: new Headers(Object.assign({ "Content-Type": "application/octet-stream", "Content-Length": String(request.length) }, headers)),
                    body: request,
                });
                let body = await resp.arrayBuffer();
                return {
                    statusCode: resp.status,
                    headers: resp.headers,
                    data: new Uint8Array(body)
                };
            }
            static fileUpload(url, uploadParameters, data) {
                return new Promise((resolve, reject) => {
                    const form = new FormData();
                    for (const key in uploadParameters) {
                        form.append(key, uploadParameters[key]);
                    }
                    form.append('file', data);
                    const fetchCfg = {
                        method: 'PUT',
                        body: form,
                    };
                    fetch(url, fetchCfg)
                        .then(response => response.json())
                        .then(res => {
                        resolve({
                            headers: res.headers,
                            statusCode: res.statusCode,
                            statusMessage: res.statusMessage
                        });
                    })
                        .catch(error => {
                        console.error('Error uploading file:', error);
                        reject(error);
                    });
                });
            }
            static async createCryptoWorker(keyStorage, options) {
                const config = Object.assign({ createWorker: async () => new BrowserCryptoWorker(), numThreads: navigator.hardwareConcurrency || 2, getKey: async (keyId, type) => {
                        switch (type) {
                            case 'cbc':
                            case 'gcm': {
                                const key = await this.loadKey(keyId, type, keyStorage);
                                const buffer = await crypto.subtle.exportKey('raw', key);
                                return new Uint8Array(buffer);
                            }
                            case 'ecc': {
                                const key = await this.loadKey(keyId, type, keyStorage);
                                const jwk = await crypto.subtle.exportKey('jwk', key);
                                return this.stringToBytes(JSON.stringify(jwk));
                            }
                            default:
                                return this.loadKeyBytes(keyId, keyStorage);
                        }
                    } }, options);
                workerPool = new CryptoWorkerPool(config);
                await workerPool.open();
                return workerPool;
            }
            static async closeCryptoWorker() {
                if (!workerPool)
                    return;
                try {
                    await workerPool.close();
                    workerPool = null;
                }
                catch (e) {
                    console.error(e);
                }
            }
            static createWebsocket(url) {
                socket = new WebSocket(url);
                let createdSocket;
                return createdSocket = {
                    onOpen: (callback) => {
                        socket.onopen = (e) => {
                            callback();
                        };
                    },
                    close: () => {
                        socket.close();
                    },
                    onClose: (callback) => {
                        socket.addEventListener("close", callback);
                    },
                    onError: (callback) => {
                        socket.addEventListener("error", callback);
                    },
                    onMessage: (callback) => {
                        socket.onmessage = async (e) => {
                            const pmArrBuff = await e.data.arrayBuffer();
                            const pmUint8Buff = new Uint8Array(pmArrBuff);
                            callback(pmUint8Buff);
                        };
                    },
                    send: (message) => {
                        socketSendMessage(message, socket, createdSocket);
                    },
                    messageQueue: [],
                };
            }
            static log(message, options) {
                if (options === 'CR')
                    return;
                console.log(message);
            }
        },
        _a.supportsConcurrency = true,
        _a.base64ToBytes = base64ToBytes,
        _a.keys = getKeeperKeys(_a.normal64Bytes),
        _a);
    function base64ToHex(data) {
        let raw = atob(data);
        let hex = '';
        for (let i = 0; i < raw.length; i++) {
            let _hex = raw.charCodeAt(i).toString(16);
            hex += (_hex.length == 2 ? _hex : '0' + _hex);
        }
        return hex;
    }
    function hexToBytes(data) {
        let bytes = [];
        for (let c = 0; c < data.length; c += 2)
            bytes.push(parseInt(data.substr(c, 2), 16));
        return Uint8Array.from(bytes);
    }
    function bytesToHex(data) {
        let hex = [];
        for (let i = 0; i < data.length; i++) {
            let current = data[i] < 0 ? data[i] + 256 : data[i];
            hex.push((current >>> 4).toString(16));
            hex.push((current & 0xF).toString(16));
        }
        return hex.join("");
    }
    const OPCODE_PING = new Uint8Array([0x9]);
    setInterval(() => {
        if (!socket)
            return;
        if (socket.readyState !== WebSocket.OPEN)
            return;
        socket.send(OPCODE_PING);
    }, 10000);
    let keyBytesCache = {};
    let cryptoKeysCache = {
        cbc: {},
        gcm: {},
        ecc: {},
    };
    class BrowserCryptoWorker {
        constructor() {
            const url = location.origin + '/worker/browserWorker.js';
            this.worker = new Worker(url);
        }
        sendMessage(message) {
            return new Promise((resolve, reject) => {
                this.worker.onmessage = function onWorkerMessage(e) {
                    resolve(e.data);
                };
                this.worker.onerror = function onWorkerError(e) {
                    reject(`Worker error: ${e.message}`);
                };
                this.worker.postMessage(message);
            });
        }
        async terminate() {
            this.worker.terminate();
        }
    }

    connectPlatform(browserPlatform);
    self.addEventListener('message', async function (e) {
        const { data } = e;
        const response = await handleCryptoWorkerMessage(data);
        // @ts-ignore
        self.postMessage(response);
    });

})();
//# sourceMappingURL=browserWorker.js.map
