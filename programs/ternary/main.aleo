// The 'main.aleo' program.
program main.aleo;
        
function hello_1:
    input r0 as u16.public;
    input r1 as u16.public;
    is.eq r0 r1 into r2;
    ternary r2 r0 r1 into r3;
    output r3 as u16.public;

function hello_2:
    input r0 as u16.private;
    input r1 as u16.private;
    is.eq r0 r1 into r2;
    ternary r2 r0 r1 into r3;
    output r3 as u16.private;

function hello_3:
    input r0 as u16.public;
    input r1 as u16.public;
    is.eq r0 r1 into r2;
    ternary r2 r0 r1 into r3;
    output r3 as u16.private;

function hello_4:
    input r0 as u32.public;
    input r1 as u32.public;
    is.eq r0 r1 into r2;
    ternary r2 r0 r1 into r3;
    output r3 as u32.public;

function hello_5:
    input r0 as u32.private;
    input r1 as u32.private;
    is.eq r0 r1 into r2;
    ternary r2 r0 r1 into r3;
    output r3 as u32.private;

function hello_6:
    input r0 as u32.public;
    input r1 as u32.public;
    is.eq r0 r1 into r2;
    ternary r2 r0 r1 into r3;
    output r3 as u32.private;

function hello_7:
    input r0 as u64.public;
    input r1 as u64.public;
    is.eq r0 r1 into r2;
    ternary r2 r0 r1 into r3;
    output r3 as u64.public;

function hello_8:
    input r0 as u64.private;
    input r1 as u64.private;
    is.eq r0 r1 into r2;
    ternary r2 r0 r1 into r3;
    output r3 as u64.private;

function hello_9:
    input r0 as u64.public;
    input r1 as u64.public;
    is.eq r0 r1 into r2;
    ternary r2 r0 r1 into r3;
    output r3 as u64.private;

function hello_10:
    input r0 as u8.public;
    input r1 as u8.public;
    is.eq r0 r1 into r2;
    ternary r2 r0 r1 into r3;
    output r3 as u8.public;

function hello_11:
    input r0 as u8.private;
    input r1 as u8.private;
    is.eq r0 r1 into r2;
    ternary r2 r0 r1 into r3;
    output r3 as u8.private;

function hello_12:
    input r0 as u8.public;
    input r1 as u8.public;
    is.eq r0 r1 into r2;
    ternary r2 r0 r1 into r3;
    output r3 as u8.private;
