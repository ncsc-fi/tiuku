import Table from 'react-bootstrap/Table';
import globeIcon from 'bootstrap-icons/icons/globe.svg';

import {
  Issues,
  IssuesTr
} from '../../common/ui';

const KrbtgtUsers = ({krbtgtUsers}) => (
  <>
    <h2><img height="32" alt="" src={globeIcon} /> KRBTGT users</h2>
    <div className="card text-secondary mb-1">
      <div className="card-body">
        <ul className="m-0">
          <li>If an attacker has gained access to a KRBTGT user's password, they can take over any account on the domain.</li>
          <li><a href="https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn745899(v=ws.11)?redirectedfrom=MSDN#krbtgt-account-maintenance-considerations">Microsoft recommends</a> changing the passwords regularly.</li>
        </ul>
      </div>
    </div>
    <Table>
      <thead>
        <tr>
          <th>Issues</th>
          <th>Domain</th>
          <th>Username</th>
          <th>Created</th>
          <th>Password changed</th>
        </tr>
      </thead>
      <tbody>
        {krbtgtUsers.map(user => (
          <IssuesTr key={`${user.domain}${user.name}`} issues={user.issues}>
            <td><Issues issues={user.issues} /></td>
            <td>{user.domain}</td>
            <td>{user.name}</td>
            <td>{user.created.toISOString()}</td>
            <td>{user.passwordChanged.toISOString()}</td>
          </IssuesTr>
        ))}
      </tbody>
    </Table>
  </>
);

export default KrbtgtUsers;
