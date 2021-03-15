import Table from 'react-bootstrap/Table';
import personIcon from 'bootstrap-icons/icons/person-circle.svg';

import {
  Issues,
  IssuesTr
} from '../../common/ui';

const Users = ({users}) => (
  <>
    <h2><img height="32" alt="" src={personIcon} /> Users</h2>
    <div className="card text-secondary mb-1">
      <div className="card-body">
        <ul className="m-0">
          <li>Check for users who should not have an account (e.g. former employees).</li>
          <li>MFA should be Enforced to protect users against attacks like <a href="https://en.wikipedia.org/wiki/Credential_stuffing">credential stuffing</a>.</li>
          <li>The MFA column is empty for accounts whose MFA state could not be retrieved during data collection.</li>
        </ul>
      </div>
    </div>
    <Table>
      <thead>
        <tr>
          <th>Issues</th>
          <th>Display name</th>
          <th>User principal name</th>
          <th>MFA</th>
        </tr>
      </thead>
      <tbody>
        {
          users.map(user => (
            <IssuesTr key={user.userPrincipalName} issues={user.issues}>
              <td><Issues issues={user.issues} /></td>
              <td className="text-break">{user.displayName}</td>
              <td className="text-break">{user.userPrincipalName}</td>
              <td>{user.mfaState}</td>
            </IssuesTr>
          ))
        }
      </tbody>
    </Table>
  </>
);

export default Users;
