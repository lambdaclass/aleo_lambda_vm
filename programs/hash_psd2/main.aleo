// The 'main.aleo' program.
program main.aleo;
        
function hello_1:
    input r0 as u16.public;
    hash.psd2 r0 into r1;
    output r1 as field.public;

function hello_2:
    input r0 as u16.private;
    hash.psd2 r0 into r1;
    output r1 as field.private;

function hello_3:
    input r0 as u16.public;
    hash.psd2 r0 into r1;
    output r1 as field.private;

function hello_4:
    input r0 as u32.public;
    hash.psd2 r0 into r1;
    output r1 as field.public;

function hello_5:
    input r0 as u32.private;
    hash.psd2 r0 into r1;
    output r1 as field.private;

function hello_6:
    input r0 as u32.public;
    hash.psd2 r0 into r1;
    output r1 as field.private;

function hello_7:
    input r0 as u64.public;
    hash.psd2 r0 into r1;
    output r1 as field.public;

function hello_8:
    input r0 as u64.private;
    hash.psd2 r0 into r1;
    output r1 as field.private;

function hello_9:
    input r0 as u64.public;
    hash.psd2 r0 into r1;
    output r1 as field.private;

function hello_10:
    input r0 as u8.public;
    hash.psd2 r0 into r1;
    output r1 as field.public;

function hello_11:
    input r0 as u8.private;
    hash.psd2 r0 into r1;
    output r1 as field.private;

function hello_12:
    input r0 as u8.public;
    hash.psd2 r0 into r1;
    output r1 as field.private;
