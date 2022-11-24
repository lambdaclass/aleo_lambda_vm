// The 'main.aleo' program.
program main.aleo;
        
record credits:
    owner as address.private;
    gates as u64.private;

function hello_1:
    input r0 as credits.record;
    input r1 as u64.public;
    add r0.gates r1 into r2;
    output r2 as u64.public;

function hello_2:
    input r0 as credits.record;
    input r1 as u64.public;
    subtract r0.gates r1 into r2;
    output r2 as u64.public;
