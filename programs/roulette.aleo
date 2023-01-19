// The 'bets.aleo' program.

program bets.aleo;

record token:
    owner as address.private;
    gates as u64.private;
    amount as u64.private;

function psd_hash:
    input r0 as u32.public;
    hash.psd2 r0 into r1;
    output r1 as field.private;

function mint_casino_token_record:
    // casino address
    input r0 as address.private;
    // casino amount of tokens
    input r1 as u64.private;
    cast r0 0u64 r1 into r2 as token.record;
    output r2 as token.record;

function make_bet:
    // casino token record
    input r0 as token.record;
    // player address
    input r1 as address.private;
    // Random roulette spin result
    input r2 as u8.private;
    // Player bet number
    input r3 as u8.private;
    // Player bet amount of tokens
    input r4 as u64.private;
    // Player amount of available tokens
    input r5 as u64.private;
    
    //r6 is true if the player wins
    is.eq r3 r2 into r6;

    //Reward
    mul r4 35u64 into r7;

    //Casino amount of tokens if it wins 
    add r0.amount r4 into r8;
    //Casino amount of tokens if it loses
    sub r0.amount r7 into r9;

    //Player amount of tokens if it wins 
    add r5 r7 into r10;
    //Player amount of tokens if it loses 
    sub r5 r4 into r11;

    //r6 is true if player wins
    //r12 casino money after game
    ternary r6 r9 r8 into r12;
    //r13 player money after game
    ternary r6 r10 r11 into r13;

    // Casino token record after the bet
    cast r0.owner r0.gates r12 into r14 as token.record;
    // Player token record after the bet
    cast r1 0u64 r13 into r15 as token.record;

    //Casino new token record
    output r14 as token.record;
    //Player new token record
    output r15 as token.record;

function psd_bits_mod:
    input r0 as boolean.public;
    input r1 as boolean.public;
    input r2 as boolean.public;
    input r3 as boolean.public;
    input r4 as boolean.public;
    input r5 as boolean.public;
    input r6 as u16.public;

    add 1u16 0u16 into r7;
    add 2u16 0u16 into r8;
    add 4u16 0u16 into r9;
    add 8u16 0u16 into r10;
    add 16u16 0u16 into r11;
    add 32u16 0u16 into r12;

    ternary r5 r7 0u16 into r13;
    ternary r4 r8 0u16 into r14;
    ternary r3 r9 0u16 into r15;
    ternary r2 r10 0u16 into r16;
    ternary r1 r11 0u16 into r17;
    ternary r0 r12 0u16 into r18;

    add r13 r14 into r19;
    add r15 r19 into r20;
    add r16 r20 into r21;
    add r17 r21 into r22;
    add r18 r22 into r23;

    div r23 37u16 into r24;
    mul 37u16 r24 into r25;
    sub r23 r25 into r26;

    is.eq r26 r6 into r27;

    output r27 as boolean.public;
