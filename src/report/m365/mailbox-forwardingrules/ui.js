import Table from 'react-bootstrap/Table';
import mailboxIcon from 'bootstrap-icons/icons/mailbox.svg';

const MailboxesForwardingRules = ({mailboxForwarding}) => (
  <>
    <h2><img height="32" alt="" src={mailboxIcon} /> Mailbox forwarding rules</h2>
    <div className="card text-secondary mb-1">
      <div className="card-body">
        <ul className="m-0">
          <li>Check for suspicious forwarding rules. They may be have been set up by attackers to get access to your organization's mailboxes.</li>
        </ul>
      </div>
    </div>
    <Table>
      <thead>
        <tr>
          <th>Display name</th>
          <th>User principal name</th>
          <th>Forwarding rule</th>
        </tr>
      </thead>
      {
      mailboxForwarding != null ?
      <tbody>
        {
          mailboxForwarding.map(forward => (
            <tr key={forward.userPrincipalName}>
              <td className="text-break">{forward.displayName}</td>
              <td className="text-break">{forward.userPrincipalName}</td>
              <td className="text-break">{forward.forwardingAddress}</td>
            </tr>
          ))
        }
      </tbody>
      : <tr><td>Could not read mailbox forwarding rules</td></tr>
      }
    </Table>
  </>
);

export default MailboxesForwardingRules;
