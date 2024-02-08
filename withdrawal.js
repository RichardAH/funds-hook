

if (process.argv.length < 6)
{
    console.log("Usage: node withdraw.js <dest-raddr> <withdraw-amount> <ripple-epoc-expiry-time> <withdraw-seq> "
                + " [signing-secret]");
    process.exit(1);
}

const rkp = require('ripple-keypairs');
const rac = require('ripple-address-codec');

const destraw = process.argv[2];
const amtraw = process.argv[3];
const expraw = process.argv[4];
const seqraw = process.argv[5];

let dest;

try{
    dest = rac.decodeAccountID(destraw);
} catch (e) {
    console.log("Invalid r-address: `" + destraw + "`" );
    process.exit(2);
}


let amt;
try {
    amt = parseFloat(amtraw);
    if (amt <= 0)
        throw new Error("");

} catch (e) {
    console.log("Invalid amount: `" + amtraw + "`");
    process.exit(3);
}

let expiry;
try {
    expiry = parseInt(expraw);
    if (expiry <= 0)
        throw new Error("");
} catch (e) {
    console.log("Invalid expiry (should be ripple epoc int)");
    process.exit(4);
}

let seq;
try {
    seq = parseInt(seqraw);
    if (seq <= 0)
        throw new Error("");
} catch (e) {
    console.log("Invalid sequence (should be positive int)");
    process.exit(5);
}

const is_new_key = (process.argv.length == 6);

const gensec = rkp.generateSeed();

let keys;

try {
    keys = rkp.deriveKeypair(is_new_key ? gensec :  process.argv[6]);
} catch (e) {
    console.log("Invalid signing secret");
    process.exit(6);
}


if (is_new_key)
{
    console.log("Your new signing secret is: " + gensec);
    console.log("The public key is: " + keys.publicKey);
}


const DEBUG = true;

const minMantissa = 1000000000000000n
const maxMantissa = 9999999999999999n
const minExponent = -96
const maxExponent = 80

function make_xfl(exponent, mantissa)
{
    // convert types as needed
    if (typeof(exponent) != 'bigint')
        exponent = BigInt(exponent);

    if (typeof(mantissa) != 'bigint')
        mantissa = BigInt(mantissa);

    // canonical zero
    if (mantissa == 0n)
        return 0n;

    // normalize
    let is_negative = mantissa < 0;
    if (is_negative)
        mantissa *= -1n;

    while (mantissa > maxMantissa)
    {
        mantissa /= 10n;
        exponent++;
    }
    while (mantissa < minMantissa)
    {
        mantissa *= 10n;
        exponent--;
    }

    // canonical zero on mantissa underflow
    if (mantissa == 0)
        return 0n;

    // under and overflows
    if (exponent > maxExponent || exponent < minExponent)
        return -1; // note this is an "invalid" XFL used to propagate errors

    exponent += 97n;

    let xfl = (!is_negative ? 1n : 0n);
    xfl <<= 8n;
    xfl |= BigInt(exponent);
    xfl <<= 54n;
    xfl |= BigInt(mantissa);

    return xfl;
}


function to_string(xfl)
{
    if (xfl < 0n)
        throw "Invalid XFL";
    if (xfl == 0n)
        return "<zero>";
    return (is_negative(xfl) ? "-" : "+") +
            get_mantissa(xfl) + " * 10**(" + get_exponent(xfl) + ")";

}


    // packed data format
    // <20 byte dest accid><8 byte le xfl amount><4 byte le int expiry timestamp><4 byte le int nonce><signature>
    

    // account

    let acchex = dest.toString('hex').toUpperCase();
    if (acchex.length != 40)
    {
        console.error("Error decoding account.");
        process.exit(8);
    }


    // amount

    let exponent = 0;
    while (amt % 1 > 0)
    {
        amt *= 10;
        exponent--;
    }

    const xfl = make_xfl(exponent, amt);

    if (DEBUG)
        console.error('DEBUG: xfl=', xfl);

    let xflhex = xfl.toString(16).toUpperCase();
    if (xflhex.length > 16)
    {
        console.error("Ivalid balance on account root (> 16 nibbles).")
        process.exit(9);
    }
    else if (xflhex.length < 16)
        xflhex = '0'.repeat(16 - xflhex.length) + xflhex;

    // flip endianness
    xflhex = xflhex.match(/../g).reverse().join('');



    // expiry

    exphex = expiry.toString(16).toUpperCase();
    if (exphex.length > 8)
    {
        console.error("Invalid expiry (> 8 nibbles).");
        process.exit(10);
    }
    else if (exphex.length < 8)
        exphex = '0'.repeat(8 - exphex.length) + exphex;


    // flip endianness
    exphex = exphex.match(/../g).reverse().join('');



    // nonce
    seqhex = seq.toString(16).toUpperCase();
    if (seqhex.length > 8)
    {
        console.error("Invalid seq (> 8 nibbles).");
        process.exit(10);
    }
    else if (seqhex.length < 8)
        seqhex = '0'.repeat(8 - seqhex.length) + seqhex;


    // flip endianness
    seqhex = seqhex.match(/../g).reverse().join('');


    const hex = acchex + xflhex + exphex + seqhex;

    const sig = rkp.sign(hex, keys.privateKey).toUpperCase();
    console.log("Withdrawal Ticket: " + hex + sig);

    if (DEBUG)
        console.error('DEBUG: verify=' + rkp.verify(hex, sig, keys.publicKey));
    process.exit(0);

