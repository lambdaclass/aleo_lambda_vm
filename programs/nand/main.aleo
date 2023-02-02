// The 'main.aleo' program.
program main.aleo;

function hello_1:
    input r0 as boolean.public;
    input r1 as boolean.public;
    nand r0 r1 into r2;
    output r2 as boolean.public;

function hello_2:
    input r0 as boolean.private;
    input r1 as boolean.private;
    nand r0 r1 into r2;
    output r2 as boolean.private;

function hello_3:
    input r0 as boolean.public;
    input r1 as boolean.public;
    nand r0 r1 into r2;
    output r2 as boolean.private;

function hello_4:
    input r0 as u8.public;
    input r1 as u8.public;
    nand r0 r1 into r2;
    output r2 as u8.public;

function hello_5:
    input r0 as u8.private;
    input r1 as u8.private;
    nand r0 r1 into r2;
    output r2 as u8.private;

function hello_6:
    input r0 as u8.public;
    input r1 as u8.public;
    nand r0 r1 into r2;
    output r2 as u8.private;
        
function hello_7:
    input r0 as u16.public;
    input r1 as u16.public;
    nand r0 r1 into r2;
    output r2 as u16.public;

function hello_8:
    input r0 as u16.private;
    input r1 as u16.private;
    nand r0 r1 into r2;
    output r2 as u16.private;

function hello_9:
    input r0 as u16.public;
    input r1 as u16.public;
    nand r0 r1 into r2;
    output r2 as u16.private;

function hello_10:
    input r0 as u32.public;
    input r1 as u32.public;
    nand r0 r1 into r2;
    output r2 as u32.public;

function hello_11:
    input r0 as u32.private;
    input r1 as u32.private;
    nand r0 r1 into r2;
    output r2 as u32.private;

function hello_12:
    input r0 as u32.public;
    input r1 as u32.public;
    nand r0 r1 into r2;
    output r2 as u32.private;

function hello_13:
    input r0 as u64.public;
    input r1 as u64.public;
    nand r0 r1 into r2;
    output r2 as u64.public;

function hello_14:
    input r0 as u64.private;
    input r1 as u64.private;
    nand r0 r1 into r2;
    output r2 as u64.private;

function hello_15:
    input r0 as u64.public;
    input r1 as u64.public;
    nand r0 r1 into r2;
    output r2 as u64.private;

function hello_16:
    input r0 as i8.public;
    input r1 as i8.public;
    nand r0 r1 into r2;
    output r2 as i8.public;

function hello_17:
    input r0 as i8.private;
    input r1 as i8.private;
    nand r0 r1 into r2;
    output r2 as i8.private;

function hello_18:
    input r0 as i8.public;
    input r1 as i8.public;
    nand r0 r1 into r2;
    output r2 as i8.private;
