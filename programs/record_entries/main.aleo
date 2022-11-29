// The 'foo.aleo' program.
program foo.aleo;

record record1:
    owner as address.private;
    gates as u64.private;
    amount as u64.public;

record record2:
    owner as address.private;
    gates as u64.private;
    amount as u64.private;

// fails
function hello_1:
    input r0 as address.private;
    input r1 as u64.private;
    input r2 as u64.public;
    cast r0 r1 r2 into r3 as record1.record;
    output r3 as record1.record;

// it works
function hello_2:
    input r0 as address.private;
    input r1 as u64.private;
    cast r0 0u64 r1 into r2 as record1.record;
    output r2 as record1.record;

// fails
function hello_3:
    input r0 as address.private;
    input r1 as u64.private;
    cast r0 r1 0u64 into r2 as record1.record;
    output r2 as record1.record;

// fails
function hello_4:
    input r0 as address.private;
    input r1 as u64.private;
    input r2 as u64.public;
    cast r0 r1 r2 into r3 as record2.record;
    output r3 as record2.record;

// it works
function hello_5:
    input r0 as address.private;
    input r1 as u64.private;
    cast r0 0u64 r1 into r2 as record2.record;
    output r2 as record2.record;

// fails
function hello_6:
    input r0 as address.private;
    input r1 as u64.private;
    cast r0 r1 0u64 into r2 as record2.record;
    output r2 as record2.record;
