import Table from 'react-bootstrap/Table';
import keyIcon from 'bootstrap-icons/icons/key.svg';
import {
  enabledString,
  Issues,
  IssuesTr
} from '../../common/ui';

const SettingRow = ({name, item}) => {
  const children = (
    <>
      <td>{item.issues ? <Issues issues={item.issues} /> : null}</td>
      <td>{name}</td>
      <td>{typeof item.value === 'boolean' ? enabledString(item.value) : item.value}</td>
    </>
  );
  return item.issues ? <IssuesTr issues={item.issues}>{children}</IssuesTr> : <tr>{children}</tr>;
};

const PasswordPolicy = ({passwordPolicy}) => (
  <>
    <h2><img height="32" alt="" src={keyIcon} /> Password policy</h2>
    <div className="card text-secondary mb-1">
      <div className="card-body">
        <ul className="m-0">
          <li>The password policy is automatically checked against <a href="https://www.microsoft.com/en-us/download/details.aspx?id=55319">Microsoft Security Compliance Toolkit 1.0.</a></li>
          <li>A weak password policy can make attacks against the users' passwords easier.</li>
        </ul>
      </div>
    </div>
    <Table>
      <thead>
        <tr>
          <th>Issues</th>
          <th>Setting</th>
          <th>Value</th>
        </tr>
      </thead>
        { 
        passwordPolicy != null ?
        <tbody>
        <SettingRow name="Minimum password length" item={passwordPolicy.minLength} />
        <SettingRow name="Enforce password history" item={passwordPolicy.historySize} />
        <SettingRow name="Password must meet complexity requirements" item={passwordPolicy.complexityCheckEnabled} />
        <SettingRow name="Store passwords using reversible encryption" item={passwordPolicy.reversibleEncryptionEnabled} />
        <SettingRow name="Account lockout duration (minutes)" item={passwordPolicy.lockout.duration} />
        <SettingRow name="Account lockout threshold" item={passwordPolicy.lockout.threshold} />
        <SettingRow name="Reset account lockout counter after (minutes)" item={passwordPolicy.lockout.resetCounterAfter} />
        </tbody>
        : <tr><td>Could not read password policy</td></tr>
        }
    </Table>
  </>
);

export default PasswordPolicy;
