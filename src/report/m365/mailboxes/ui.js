import Table from 'react-bootstrap/Table';
import mailboxIcon from 'bootstrap-icons/icons/mailbox.svg';

import {enabledString} from '../../common/ui';

const Mailboxes = ({mailboxes}) => (
  <>
    <h2><img height="32" alt="" src={mailboxIcon} /> Mailboxes</h2>
    <div className="card text-secondary mb-1">
      <div className="card-body">
        <ul className="m-0">
          <li>Check for mailboxes that should not exist (e.g. for former employees).</li>
          <li>Audit logging should be Enabled for all users. Audit logs can be used to detect and investigate unauthorized activity.</li>
        </ul>
      </div>
    </div>
    <Table>
      <thead>
        <tr>
          <th>Display name</th>
          <th>User principal name</th>
          <th>Audit log</th>
          <th>Default audit set</th>
        </tr>
      </thead>
      <tbody>
        {
          mailboxes.map(mailbox => (
            <tr key={mailbox.userPrincipalName}>
              <td className="text-break">{mailbox.displayName}</td>
              <td className="text-break">{mailbox.userPrincipalName}</td>
              <td>{enabledString(mailbox.isAuditEnabled)}</td>
              <td>
                {
                  mailbox.defaultAuditSet.map(auditset => (
                    <div key={`${mailbox.userPrincipalName}--${auditset}`}>
                      <span>{auditset}</span>
                    </div>
                  ))
                }
              </td>
            </tr>
          ))
        }
      </tbody>
    </Table>
  </>
);

export default Mailboxes;
