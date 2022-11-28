program credits.aleo;

record credits:
    owner as address.private;
    gates as u64.private;

function genesis:
    input r0 as address.private;
    input r1 as u64.private;
    cast r0 r1 into r2 as credits.record;
    output r2 as credits.record;

function mint:
    input r0 as address.private;
    input r1 as u64.private;
    cast r0 r1 into r2 as credits.record;
    output r2 as credits.record;

function transfer:
    input r0 as credits.record;
    input r1 as address.private;
    input r2 as u64.private;
    sub r0.gates r2 into r3;
    cast r1 r2 into r4 as credits.record;
    cast r0.owner r3 into r5 as credits.record;
    output r4 as credits.record;
    output r5 as credits.record;

function combine:
    input r0 as credits.record;
    input r1 as credits.record;
    add r0.gates r1.gates into r2;
    cast r0.owner r2 into r3 as credits.record;
    output r3 as credits.record;

function split:
    input r0 as credits.record;
    input r1 as u64.private;
    sub r0.gates r1 into r2;
    cast r0.owner r1 into r3 as credits.record;
    cast r0.owner r2 into r4 as credits.record;
    output r3 as credits.record;
    output r4 as credits.record;

function fee:
    input r0 as credits.record;
    input r1 as u64.private;
    sub r0.gates r1 into r2;
    cast r0.owner r2 into r3 as credits.record;
    output r3 as credits.record;
