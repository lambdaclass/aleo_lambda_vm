// The 'main.aleo' program.
program main.aleo;
        
function hello_1:
    input r0 as u16.public;
    input r1 as u16.public;
    assert.eq r0 r1 into r2;
    assert.neq r0 r1 into r3;
    output r2 as u16.public;
    output r3 as u16.public;

function hello_2:
    input r0 as u16.private;
    input r1 as u16.private;
    assert.eq r0 r1 into r2;
    assert.neq r0 r1 into r3;
    output r2 as u16.public;
    output r3 as u16.public;


function hello_3:
    input r0 as u16.public;
    input r1 as u16.public;
    assert.eq r0 r1 into r2;
    assert.neq r0 r1 into r3;
    output r2 as u16.public;
    output r3 as u16.public;


function hello_4:
    input r0 as u32.public;
    input r1 as u32.public;
    assert.eq r0 r1 into r2;
    assert.neq r0 r1 into r3;
    output r2 as u32.public;
    output r3 as u32.public;

function hello_5:
    input r0 as u32.private;
    input r1 as u32.private;
    assert.eq r0 r1 into r2;
    assert.neq r0 r1 into r3;
    output r2 as u32.private;
    output r3 as u32.private;

function hello_6:
    input r0 as u32.public;
    input r1 as u32.public;
    assert.eq r0 r1 into r2;
    assert.neq r0 r1 into r3;
    output r2 as u32.public;
    output r3 as u32.public;

function hello_7:
    input r0 as u64.public;
    input r1 as u64.public;
    assert.eq r0 r1 into r2;
    assert.neq r0 r1 into r3;
    output r2 as u64.public;
    output r3 as u64.public;

function hello_8:
    input r0 as u64.private;
    input r1 as u64.private;
    assert.eq r0 r1 into r2;
    assert.neq r0 r1 into r3;
    output r2 as u64.private;
    output r3 as u64.private;

function hello_9:
    input r0 as u64.public;
    input r1 as u64.public;
    assert.eq r0 r1 into r2;
    assert.neq r0 r1 into r3;
    output r2 as u64.public;
    output r3 as u64.public;

function hello_10:
    input r0 as u8.public;
    input r1 as u8.public;
    assert.eq r0 r1 into r2;
    assert.neq r0 r1 into r3;
    output r2 as u8.public;
    output r3 as u8.public;

function hello_11:
    input r0 as u8.private;
    input r1 as u8.private;
    assert.eq r0 r1 into r2;
    assert.neq r0 r1 into r3;
    output r2 as u8.private;
    output r3 as u8.private;

function hello_12:
    input r0 as u8.public;
    input r1 as u8.public;
    assert.eq r0 r1 into r2;
    assert.neq r0 r1 into r3;
    output r2 as u8.public;
    output r3 as u8.public;