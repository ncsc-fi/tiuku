import Table from 'react-bootstrap/Table';
import globeIcon from 'bootstrap-icons/icons/globe.svg';

const DomainAdmins = ({domainAdmins}) => (
  <>
    <h2><img height="32" alt="" src={globeIcon} /> Domain admins</h2>
    <div className="card text-secondary mb-1">
      <div className="card-body">
        <ul className="m-0">
          <li>A compromise of any of the domain admin accounts will lead to a complete compromise of the whole domain.</li>
          <li>You should remove the domain admin permissions from any user that is not absolutely required to have them.</li>
        </ul>
      </div>
    </div>
    <Table>
      <thead>
        <tr>
          <th>Group domain</th>
          <th>Group name</th>
          <th>Member domain</th>
          <th>Member name</th>
          <th>Member distinguished name</th>
        </tr>
      </thead>
      <tbody>
        {
          domainAdmins.map(domainadmin => (
            <tr key={domainadmin.memberDistinguishedName}>
              <td className="text-break">{domainadmin.groupDomain}</td>
              <td className="text-break">{domainadmin.groupName}</td>
              <td className="text-break">{domainadmin.memberDomain}</td>
              <td className="text-break">{domainadmin.memberName}</td>
              <td className="text-break">{domainadmin.memberDistinguishedName}</td>
            </tr>
          ))
        }
      </tbody>
    </Table>
  </>
);

export default DomainAdmins;
