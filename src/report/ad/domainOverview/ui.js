import Table from 'react-bootstrap/Table';
import infoIcon from 'bootstrap-icons/icons/info-circle.svg';

const DomainOverview = ({domainOverview}) => (
  <>
    <h2><img height="32" alt="" src={infoIcon} /> Domain overview</h2>
    <div className="card text-secondary mb-1">
      <div className="card-body">
        <ul className="m-0">
          <li>If the number of administrator users is very high compared to the size of the organization and its domains, it might indicate that some users have administrator permissions that they don't really need.</li>
          <li>If some computers in the domain are running old operating systems that no longer receive security updates, they may have unpatched vulnerabilities.</li>
        </ul>
      </div>
    </div>
    <Table>
      <tbody>
        <tr>
          <td className="col-5">Number of users in domain</td>
          <td>{domainOverview.userCount}</td>
        </tr>
        <tr>
          <td className="col-5">Number of users in Domain Admins group</td>
          <td>{domainOverview.domainAdminGroupUserCount}</td>
        </tr>
        <tr>
          <td className="col-5">Number of users with <span className="text-monospace">AdminCount = 1</span></td>
          <td>{domainOverview.domainAdminGroupUserCount}</td>
        </tr>
        <tr>
          <td className="col-5">Number of groups in domain</td>
          <td>{domainOverview.groupCount}</td>
        </tr>
        <tr>
          <td className="col-5">Number of computers in domain</td>
          <td>
            <Table>
              <tbody>
                {Object.entries(domainOverview.computerCountByOs).sort().map(([os, count]) => (
                  <tr key={os}>
                    <td>{os}</td>
                    <td>{count}</td>
                  </tr>
                ))}
                <tr>
                  <td>Total</td>
                  <td>{domainOverview.computerCount}</td>
                </tr>
              </tbody>
            </Table>
          </td>
        </tr>
        <tr>
          <td className="col-5">Number of organizational units (OU)</td>
          <td>{domainOverview.organizationalUnitCount}</td>
        </tr>
        <tr>
          <td className="col-5">Number of domains in forest</td>
          <td>{domainOverview.forestDomainCount}</td>
        </tr>
      </tbody>
    </Table>
  </>
);

export default DomainOverview;
