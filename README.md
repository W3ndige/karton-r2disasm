# karton-r2disasm
Aurora karton for disassembling samples using r2pipe.

**Consumes:**
```
{
    "type":     "sample",
    "stage":    "recognized"
    "kind":     "runnable" || "dump"
    ...
} 
```

**Produces:**
```
{
    "type":     "feature",
    "stage":    "raw"
    "kind":     "disasm"  
    "payload": {
        "data":         "opcodes list",
        "sha256":       "sha256 of the sample containing the minhash"
    }
}
```