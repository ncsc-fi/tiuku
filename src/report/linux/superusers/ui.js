import Table from 'react-bootstrap/Table';
import globeIcon from 'bootstrap-icons/icons/globe.svg';

const Superusers = ({superusers}) => (
  <>
    <h2><img height="32" alt="" src={globeIcon} /> Superusers</h2>
    <Table>
      <thead>
        <tr>
          <th>Username</th>
          <th>User ID</th>
          <th>Group ID</th>
          <th>Shell</th>
        </tr>
      </thead>
      <tbody>
        {
          superusers.map(superuser => (
            <tr key={superuser.username}>
              <td className="text-break">{superuser.username}</td>
              <td className="text-break">{superuser.userId}</td>
              <td className="text-break">{superuser.groupId}</td>
              <td className="text-break">{superuser.shell}</td>
            </tr>
          ))
        }
      </tbody>
    </Table>
  </>
);

export default Superusers;
