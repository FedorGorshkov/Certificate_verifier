# Certificate verifier
This is a simple https certificate verifier service. The only method it implements is **/verify_certificate**, which takes two arguments: 
- *file* - file with certificate (any extension)
- *crt_encoding* - by default is PEM, also could be ANS1 or DER </ul>\
Service returns status_code and **JSON Response** with fields *Status* and *Message*. If status_code is OK (200), there is also boolean *Correct* field
