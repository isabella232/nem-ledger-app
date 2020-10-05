# NEM's APDU package fields

### I. Common transaction part
```
01. CLA   (1 byte)
02. INS   (1 byte)
03. P1    (1 byte)
04. P2    (1 byte)
05. LC    (1 byte)
06. CDATA (1 byte)

(Reference: https://nemproject.github.io/#gathering-data-for-the-signature)

07. Devariant path (44/43/0/0/0)   (20 bytes) (8000002C8000002B800000988000000080000000) (fixed)
08. Transaction Type               (4 bytes)  (depends on tx) (01010000)
09. Version                        (4 bytes)  (depends on tx) (01000098) (depends on network and transaction type)
10. Timestamp                      (4 bytes)  (depends on tx) (9B5CD007)
11. Public key length              (4 bytes)  (fixed) (20000000)
12. Signer Public Key              (8 bytes)  (depends on tx) (3E6E6CBAC488B8A44BDF5ABF27B9E1CC2A6F20D09D550A66B9B36F525CA222EE)
13. Fee (micro xem)                (8 bytes)  (depends on tx) (A086010000000000)
14. Deadline                       (4 bytes)  (depends on tx) (AB6AD007)
```
### II. Properties parts (Phan rieng cua cac goi tin)

# Transfer transaction schema
1. Transfer transaction part (Reference: https://nemproject.github.io/#gathering-data-for-the-signature)

```
Property                                             Types                                           Description
----------------------------------------------------------------------------------------------------------------------
recipientAddressLength                               uint32           	                             Length of recipient address (always 40)
recipientAddress 	                                 40 Bytes                                        Transaction recipient (UTF8 encoding)
amount                                               uint64                       	                 Amount of sending xem  (micro xem)
messageFieldLength                                   uint32
MessageType  (Not exist if messageFieldLength = 0)   uint32 	                                     MessageType
LengthOfPayload(Not exist if messageFieldLength = 0) uint32
Payload (Not exist if messageFieldLength = 0)        array(messageSize)                              Hexadecimal payload.

(Optional: available for version 2 transfer transactions that have an attachment.)
mosaicsNum 	                                        uint32                                          Attached mosaics to send.
mosaicArray                                         Array(mosaicNum, mosaicStructure)               Mosaic structure array
```

1.1 Mosaic structure part
```
Property                                             Types                                           Description
----------------------------------------------------------------------------------------------------------------------
MosaicStructureLength                                uint32
MosaicIdStructureLength                              unit32
NamespaceIdLength                                    uint32
MosaicNameStringLength                               uint32
MosaicName                                           Array(MosaicNameStringLength)
Quantity                                             uint64
```



Example:

Full raw transaction (ledger receive):
```
E0049080A9058000002C8000002B80000098800000008000000001010000010000989B5CD007200000003E6E6CBAC488B8A44BDF5ABF27B9E1CC2A6F20D09D550A66B9B36F525CA222EEA086010000000000AB6AD007280000005441353435494341564E45554446554249484F3343454A425356495A37595948464658354C51505440420F00000000002000000001000000180000005369676E20746573746E6574207472616E73616374696F6E

```
#### Parsed above tx
```
##### Common parts

01 -> 06                    E0049080A905
07                          8000002C8000002B800000988000000080000000
08                          01010000
09                          01000098
10                          9B5CD007
11                          20000000
12                          3E6E6CBAC488B8A44BDF5ABF27B9E1CC2A6F20D09D550A66B9B36F525CA222EE
13                          A086010000000000
14                          AB6AD007


##### Properties parts

recipientAddressLength      28000000
recipientAddress            5441353435494341564E45554446554249484F3343454A425356495A37595948464658354C515054
amount                      40420F0000000000
messageFieldLength          20000000
MessageType                 01000000
LengthOfPayload             18000000
Payload                     5369676E20746573746E6574207472616E73616374696F6E
```

# Importance Transfer transaction schema
2. Importance Transfer transaction part (Reference: https://nemproject.github.io/#gathering-data-for-the-signature)

```
Property                                             Types                                         Description
----------------------------------------------------------------------------------------------------------------------
Importance transfer mode                            uint32                                         0x01 (activate) or 0x02  (Deactivate mode)
RemoteAccountPublicKeyArrayLength                   uint32                                         Length of remote account public key byte array
RemoteAccountPublicKeyArray                         Array(32 bytes, RemoteAccountPublicKeyArrayLength)
```

#  Provision namespace Transaction schema
3. Provision namespace Transaction (Reference: https://nemproject.github.io/#gathering-data-for-the-signature)

```
Property                                Types                                       Description
----------------------------------------------------------------------------------------------------------------------
feeSinkEncodedAddressLength             uint32                                     	(fixed) (0x28)
feeSinkEncodedAddress                   40 bytes	                                Address bytes of rental fee sink
Rental fee  	                        8 bytes 	                                (fixed) (Root always: 100000000, Sub always: 10000000)
newPartStringLength                     uint32
newPartString                           array(newPartStringLength)
parentStringLength                      uint32
parentString    (optional)              array(parentStringLength)                   (if parentStringLength = FFFFFFFF) this field is omitted
```

#  Mosaic Supply Change Transaction schema
4. Mosaic Supply Change Transaction (Reference: https://nemproject.github.io/#gathering-data-for-the-signature)

```
Property                                Types                                       Description
----------------------------------------------------------------------------------------------------------------------
mosaicIdLength                         	uint32
namespaceIdStringLength                 uint32
namespaceIdString                       array(namespaceIdStringLength)
mosaicNameStringLength                  uint32
mosaicNameString                        array(mosaicNameStringLength)
supplyType                              uint32                                      0x01 (increase), 0x02 (decrease)
delta                                   uint64
```



##  Mosaic definition creation transaction part schema
5. Mosaic definition creation transaction (Reference: https://nemproject.github.io/#gathering-data-for-the-signature)

