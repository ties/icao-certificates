import assert from 'assert';
import fs from 'fs';

import asn1js from 'asn1js';
import pkijs from 'pkijs';
import { Crypto } from '@peculiar/webcrypto';

const webcrypto = new Crypto();
pkijs.setEngine("newEngine", webcrypto, new pkijs.CryptoEngine({
    name: "",
    crypto: webcrypto,
    subtle: webcrypto.subtle
}));


const ID_ICA_CSCA_MASTER_LIST = "2.23.136.1.1.2";
// CscaMasterListVersion ::= INTEGER {v0(0)}
// CscaMasterList ::= SEQUENCE {
//  version CscaMasterListVersion,
//  certList SET OF Certificate
// }
// 
// -- Object Identifiers
// id-icao-cscaMasterList OBJECT IDENTIFIER ::=
//  {id-icao-mrtd-security 2}
// id-icao-cscaMasterListSigningKey OBJECT IDENTIFIER ::=
//  {id-icao-mrtd-security 3}
// END
const CscaMasterList = new asn1js.Sequence({
  name: "CscaMasterList",
  value: [
    new asn1js.Integer({
      name: "version"
    }),
    new asn1js.Set({
      name: "certList",
      value: [pkijs.Certificate.schema()]
    })
  ]
})

var asn1_schema_internal = new asn1js.OctetString({
  name: "outer_block",
  primitiveSchema: CscaMasterList
});



try {
  const data = fs.readFileSync('./ICAO_ml_2021.04.06.ml');
  const ber = new Uint8Array(data).buffer;

  // console.log(data);
  const asn1 = asn1js.fromBER(ber);

  const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
  const signedData = new pkijs.SignedData({ schema: contentInfo.content });

  const verificationResult = await signedData.verify({
      signer: 0,
      data: asn1,
      extendedMode: true
  });

  assert.strictEqual(signedData.encapContentInfo.eContentType, ID_ICA_CSCA_MASTER_LIST);
  const certificatesOctetString = signedData.encapContentInfo.eContent;

  console.log(verificationResult);
  console.log(certificatesOctetString);

  const { result, verified } = asn1js.compareSchema(certificatesOctetString, certificatesOctetString, asn1_schema_internal);

  assert.ok(verified);
  console.log(result.toJSON());

  // Write all the certificates to individual files
  result.certList.valueBlock.value.map((cert, idx) => {
    fs.writeFileSync(`./certificate-${idx}.der`, Buffer.from(cert.toBER()));
  });
} catch (error) {
  console.log(error);
}
  // console.log(data);
// } catch (err) {
  // console.log(err);
// }
