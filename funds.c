
#include <stdint.h>
#include "hookapi.h"

#define DONE(x)\
    return accept(SBUF(x), __LINE__)

#define NOPE(x)\
    return rollback(SBUF(x), __LINE__)


uint8_t txn_out[300] =
{
/* size,upto */
/*   3,   0 */   0x12U, 0x00U, 0x00U,                                                               /* tt = Payment */
/*   5,   3 */   0x22U, 0x80U, 0x00U, 0x00U, 0x00U,                                          /* flags = tfCanonical */
/*   5,   8 */   0x24U, 0x00U, 0x00U, 0x00U, 0x00U,                                                 /* sequence = 0 */
/*   6,  13 */   0x20U, 0x1AU, 0x00U, 0x00U, 0x00U, 0x00U,                                      /* first ledger seq */
/*   6,  19 */   0x20U, 0x1BU, 0x00U, 0x00U, 0x00U, 0x00U,                                       /* last ledger seq */
/*   1,  25 */   0x61U, 
/*   8,  26 */   0,0,0,0,0,0,0,0,                                                                        /* amt val */
/*  20,  34 */   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,                                                /* amt cur */
// vvvvvvvvvvvvvvvvvv ISSUER ACC ID vvvvvvvvvvvvvvvvvvvvvvv
/*  20,  54 */   
                 0,0,0,0,0,0,0,0,0,0,
                 0,0,0,0,0,0,0,0,0,0,

/*   9,  74 */   0x68U, 0x40U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,                         /* fee      */
/*  35,  83 */   0x73U, 0x21U, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,       /* pubkey   */
/*   2, 118 */   0x81U, 0x14U,                                                                  /* src acc preamble */

/*  20, 120 */   0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0,                                             /* src acc */
/*   2, 140 */   0x83U, 0x14U,                                                                 /* dest acc preamble */
/*  20, 142 */   0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0,                                            /* dest acc */

/* 138, 162 */   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,    /* emit detail */
                 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
/*   0, 300 */
};

#define TLACC (txn_out + 54) /* set it above!! */

#define TXNLEN 300
#define FEEOUT (txn_out + 75)
#define EMITDET (txn_out + 162)
#define HOOKACC (txn_out + 120)
#define OTXNACC (txn_out + 142)
#define DESTACC (txn_out + 142)
#define OUTAMT (txn_out + 26)
#define OUTCUR (txn_out + 34)
#define OUTISS (txn_out + 54)
#define CURSHORT (txn_out + 46)

// if we make a TrustSet instead (used for initialisation) then we'll truncate the template above
#define TTOUT (txn_out + 2)         // when it's a TrustSet we set this to 0x14
#define OUTAMT_TL (txn_out + 25)    // when it's a TrustSet, we set this to 0x63
#define EMITDET_TL (txn_out + 140)  // when it's a TrustSet Emit Details occurs sooner
#define TXNLEN_TL 256               // .. and the txn is smaller

#define BE_DROPS(drops)\
{\
        uint64_t drops_tmp = drops;\
        uint8_t* b = (uint8_t*)&drops;\
        *b++ = 0b01000000 + (( drops_tmp >> 56 ) & 0b00111111 );\
        *b++ = (drops_tmp >> 48) & 0xFFU;\
        *b++ = (drops_tmp >> 40) & 0xFFU;\
        *b++ = (drops_tmp >> 32) & 0xFFU;\
        *b++ = (drops_tmp >> 24) & 0xFFU;\
        *b++ = (drops_tmp >> 16) & 0xFFU;\
        *b++ = (drops_tmp >>  8) & 0xFFU;\
        *b++ = (drops_tmp >>  0) & 0xFFU;\
}

#define COPY_20(src, dst)\
{\
    *((uint64_t*)(((uint8_t*)(dst)) + 0)) = \
    *((uint64_t*)(((uint8_t*)(src)) + 0));\
    *((uint64_t*)(((uint8_t*)(dst)) + 8)) = \
    *((uint64_t*)(((uint8_t*)(src)) + 8));\
    *((uint32_t*)(((uint8_t*)(dst)) + 16)) = \
    *((uint32_t*)(((uint8_t*)(src)) + 16));\
}

int64_t cbak(uint32_t f)
{
    return 0;
}

int64_t hook(uint32_t r)
{
    _g(1,1);

    etxn_reserve(1);

    hook_account(HOOKACC, 20);

    otxn_field(OTXNACC, 20, sfAccount);

    if (BUFFER_EQUAL_20(HOOKACC, OTXNACC))
        DONE("Funds: passing outgoing txn");

    int64_t tt = otxn_type();
    if (tt != ttINVOKE && tt != PAYMENT)
        NOPE("Funds: Rejecting non-Invoke, non-Payment txn.");

    otxn_slot(1);

    slot_subfield(1, sfAmount, 2);

    uint8_t amt[48];

    if (slot_size(2) == 8)
        DONE("Funds: Passing incoming XAH payment.");

    // get admin account
    uint8_t admin[20];
    if (hook_param(SBUF(admin), "ADM", 3) != 20)
        NOPE("Funds: Misconfigured. Missing ADM install parameter.");

    // get currency
    if (hook_param(OUTCUR, 20, "CUR", 3) != 20)
        NOPE("Funds: Misconfigured. Missing CUR install parameter.");

    // get currency issuer
    if (hook_param(OUTISS, 20, "ISS", 3) != 20)
        NOPE("Funds: Misconfigured. Missing ISS install parameter.");

    // get settlement address
    uint8_t stl[20];
    if (hook_param(SBUF(stl), "STL", 3) != 20)
        NOPE("Funds: Misconfigured. Missing STL install parameter.");


    uint8_t op;

    if (otxn_param(&op, 1, "OP") != 1)
        NOPE("Funds: Missing OP parameter on Invoke.");


    int64_t xfl_in;

    if (tt == ttPAYMENT)
    {
        // this will fail if flags isn't in the txn, that's also ok.
        otxn_field(&flags, 4, sfFlags);
        
        // check for partial payments (0x00020000) -> (0x00000200 LE)
        if (flags & 0x200U)
            NOPE("Funds: Partial payments are not supported.");
    

        if (!BUFFER_EQUAL_20(amt + 8, OUTCUR))
            NOPE("Funds: Wrong currency.");


        if (!BUFFER_EQUAL_20(amt + 28, OUTISS)
            NOPE("Funds: Wrong issuer.");

        xfl_in = slot_float(2);

        if (xfl_in < 0 || !float_compare(xfl_in, 0, COMPARE_GREATER))
            NOPE("Funds: Invalid sfAmount.");
    }


    // invoke ops are: I - initalize (admin), S - settle (admin), U/P - un/pause (admin), W - withdraw
    
    // payment ops are: D - deposit, R - refund (settlement addr)

    int64_t is_admin = BUFFER_EQUAL_20(OTXNACC, admin);

    int64_t is_stl = BUFFER_EQUAL_20(OTXNACC, stl);

    // sanity check
    if ((op == 'D' || op == 'R') && tt != ttPAYMENT)
        NOPE("Funds: Deposit/Refund operations must be a payment transaction.");

    // permission check
    if (!is_admin && (op == 'U' || op == 'P' || op == 'S'))
        NOPE("Funds: Admin only operation.");
    else if (!is_stl && op == 'R')
        NOPE("Funds: Settlement address only operation.");

    // enforced pausedness
    if (op != 'U')
    {
        uint8_t paused;
        state(&paused, 1, "P", 1);
        if (paused)
            NOPE("Funds: Paused.");
    }

    // check if the trustline exists
    uint8_t keylet[34];
    util_keylet(keylet, 34, KEYLET_LINE, HOOKACC, 20, OUTISS, 20, OUTCUR, 20);

    int64_t already_setup = (slot_set(SBUF(keylet), 10) == 10);

    // enforce initalisation
    if (!already_setup && op != 'I')
        NOPE("Funds: Send op=I initalisation first.");

    // if they are withdrawing or settling then they need an amt param
    uint64_t xfl_out;
    otxn_param(&xfl_out, 8, "AMT");

    // current ledger seq is used when emitting a txn
    int64_t seq = ledger_seq() + 1;


    // action
    switch (op)
    {
        case 'I':
        {
            if (already_setup)
                DONE("Funds: Already setup trustline.");

            // create a trustline ...
            
            // set the template transaction type to trustset
            *TTOUT = 0x14U;

            // set the amount field type to limitamount
            *OUTAMT_TL = 0x63U;

            etxn_details(EMITDET_TL, 138);
            int64_t fee = etxn_fee_base(txn_out, TXNLEN_TL);
            BE_DROPS(fee);
            *((uint64_t*)(FEEOUT)) = fee;

            txn_out[15] = (seq >> 24U) & 0xFFU;
            txn_out[16] = (seq >> 16U) & 0xFFU;
            txn_out[17] = (seq >>  8U) & 0xFFU;
            txn_out[18] = seq & 0xFFU;

            seq += 4;
            txn_out[21] = (seq >> 24U) & 0xFFU;
            txn_out[22] = (seq >> 16U) & 0xFFU;
            txn_out[23] = (seq >>  8U) & 0xFFU;
            txn_out[24] = seq & 0xFFU;
    
            trace(SBUF("emit:"), txn_out, TXNLEN_TL, 1);

            uint8_t emithash[32];
            int64_t emit_result = emit(SBUF(emithash), txn_out, TXNLEN_TL);

            DONE("Funds: Emitted TrustSet to initialize.");
        }

        case 'U':
        case 'P':
        {
            // pause
            uint8_t paused = (op == 'P' ? 1 : 0);
            state_set(&paused, 1, "P", 1);
            DONE("Funds: Paused.");
        }

        case 'R':
        {
            // refund is simple, do nothing
            DONE("Funds: Refunded.");
        }

        case 'D':
        {
            // deposit is simple, do nothing
            DONE("Funds: Deposited.");
        }


        // settlement and withdrawal
        case 'S':
        case 'W':
        {

            if (xfl_out == 0 || float_compare(xfl_out, 0, COMPARE_LESS))
                NOPE("Funds: Invalid AMT parameter.");

            // emit a txn either to the otxn acc or the settlement acc
            if (op == 'W')
            {
                // RHTODO check signature/nonce for withdrawal

            }
            else
            {
                // set the destination addr to the settlement addr
                COPY_20(stl, DESTACC); 
            }

            // check trustline balance
            slot_subfield(10, sfBalance, 11);
            if (slot_size(11) != 48)
                NOPE("Funds: Could not fetch trustline balance.");
    
            int64_t xfl_bal = slot_float(11);

            if (xfl_bal <= 0 || !float_compare(xfl_bal, 0, COMPARE_GREATER))
                NOPE("Funds: Insane balance on trustline.");

            
            // RHTODO set amount on emitted txn
            // RHTODO check amount is valid wrt trustline bal


            etxn_details(EMITDET, 138);
            int64_t fee = etxn_fee_base(txn_out, TXNLEN);
            BE_DROPS(fee);
            *((uint64_t*)(FEEOUT)) = fee;

            txn_out[15] = (seq >> 24U) & 0xFFU;
            txn_out[16] = (seq >> 16U) & 0xFFU;
            txn_out[17] = (seq >>  8U) & 0xFFU;
            txn_out[18] = seq & 0xFFU;

            seq += 4;
            txn_out[21] = (seq >> 24U) & 0xFFU;
            txn_out[22] = (seq >> 16U) & 0xFFU;
            txn_out[23] = (seq >>  8U) & 0xFFU;
            txn_out[24] = seq & 0xFFU;
    
            trace(SBUF("emit:"), txn_out, TXNLEN_TL, 1);

            uint8_t emithash[32];
            int64_t emit_result = emit(SBUF(emithash), txn_out, TXNLEN_TL);

            if (op == 'W')
                DONE("Funds: Emitted withdrawal.");

            DONE("Funds: Emitted settlement.");


            break;
        }

        default:
        {
            NOPE("Funds: Unknown operation.");
        }
    }

    return 0;
}
