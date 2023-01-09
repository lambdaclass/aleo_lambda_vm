program records.aleo;

record token:
     owner as address.private;
     gates as u64.private;
     amount as u64.public;

function mint:
     input r0 as u64.public;
     input r1 as address.public;
     cast r1 0u64 r0 into r2 as token.record;      
     output r2 as token.record;

function consume:
     input r0 as token.record;
     add r0.amount 0u64 into r1;
     output r1 as u64.public;
