import Table from 'react-bootstrap/Table';
import globeIcon from 'bootstrap-icons/icons/globe.svg';

const DnsRecords = ({dnsRecords}) => (
  <>
    <h2><img height="32" alt="" src={globeIcon} /> DNS Records</h2>
    <div className="card text-secondary mb-1">
      <div className="card-body">
        <ul className="m-0">
          <li>Check for suspicious and unused DNS records.</li>
          <li>If there are CNAME records pointing to any services your organization no longer uses, they may be vulnerable to subdomain takeover attacks.</li>
        </ul>
      </div>
    </div>
    <Table>
      <thead>
        <tr>
          <th>DNS Name</th>
          <th>Record type</th>
          <th>Zone name</th>
          <th>Records</th>
        </tr>
      </thead>
      <tbody>
        {
          dnsRecords.map(dnsRecord => (
            <tr key={dnsRecord.name}>
              <td className="text-break">{dnsRecord.name}</td>
              <td className="text-break">{dnsRecord.recordType}</td>
              <td className="text-break">{dnsRecord.zoneName}</td>
              <td className="text-break">
                {
                  dnsRecord.records.length > 0 ?
                    <table>
                      <tr>
                        <th>Key</th>
                        <th>value</th>
                      </tr>
                      {
                        dnsRecord.records.map(record => (
                          Object.entries(record).map(([key, value]) => (
                            <tr>
                              <td>{key}</td>
                              <td>{value}</td>
                            </tr>
                          ))
                        ))
                      }
                    </table>
                  : "No records"
                }
              </td>
            </tr>
          ))
        }
      </tbody>
    </Table>
  </>
);

export default DnsRecords;
