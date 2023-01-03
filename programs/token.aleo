program token.aleo;

record token:
    owner as address.private;
    gates as u64.private;
    amount as u64.private;

function mint:
    // amount to mint
    input r0 as u64.private;
    // address
    input r1 as address.private;
    // create new record
    cast r1 0u64 r0 into r2 as token.record;
    // output the new record
    output r2 as token.record;

function transfer_amount:
    //  sender token record
    input r0 as token.record;
    // receiver address
    input r1 as address.private;
    // amount to transfer
    input r2 as u64.private;
    // final balance of sender
    sub r0.amount r2 into r3;
    // final balance of receiver
    add 0u64 r2 into r4;
    // sender token record after the transfer
    cast r0.owner r0.gates r3 into r5 as token.record;
    // receiver token record after the transfer
    cast r1 0u64 r4 into r6 as token.record;
    // sender new token record
    output r5 as token.record;
    // receiver new token record
    output r6 as token.record;
    
