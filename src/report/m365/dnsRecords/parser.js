import {
  string,
  array,
  arrayOf,
  struct
} from '../../common/parser';

const recordType = (context, x) => {
  return {
    0: 'A',
    1: 'AAAA',
    2: 'CAA',
    3: 'CNAME',
    4: 'MX',
    5: 'NS',
    6: 'PTR',
    7: 'SOA',
    8: 'SRV',
    9: 'TXT'
  }[x];
};

const dnsRecord = (context, x) => {
  const o = struct({
    Name: string,
    ZoneName: string,
    RecordType: recordType,
    Records: array
  })(context, x);

  return {
    name: o.Name,
    zoneName: o.ZoneName,
    recordType: o.RecordType,
    records: o.Records
  };
};

const dnsRecords = arrayOf(dnsRecord);

export default dnsRecords;
