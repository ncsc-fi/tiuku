import Table from 'react-bootstrap/Table';
import globeIcon from 'bootstrap-icons/icons/globe.svg';

const GlobalAdmins = ({globalAdmins}) => (
  <>
    <h2><img height="32" alt="" src={globeIcon} /> Global Admins</h2>
    <div className="card text-secondary mb-1">
      <div className="card-body">
        <ul className="m-0">
          <li>A compromise of any of the global admin accounts will lead to a complete compromise of your organization's data in M365.</li>
          <li>You should remove the global admin role from any user that is not absolutely required to have it.</li>
          <li><a href="https://docs.microsoft.com/en-us/microsoft-365/admin/add-users/about-admin-roles?view=o365-worldwide#security-guidelines-for-assigning-roles">Microsoft recommends</a> having 2-4 global admins.</li>
        </ul>
      </div>
    </div>
    <Table>
      <thead>
        <tr>
          <th>Display name</th>
          <th>User principal name</th>
        </tr>
      </thead>
      <tbody>
        {
          globalAdmins.map(globalAdmin => (
            <tr key={globalAdmin.userPrincipalName}>
              <td className="text-break">{globalAdmin.displayName}</td>
              <td className="text-break">{globalAdmin.userPrincipalName}</td>
            </tr>
          ))
        }
      </tbody>
    </Table>
  </>
);

export default GlobalAdmins;
