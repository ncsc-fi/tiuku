import OverlayTrigger from 'react-bootstrap/OverlayTrigger';
import Popover from 'react-bootstrap/Popover';

export const enabledString = (x) => x ? 'Enabled' : 'Disabled';

export const IssuesTr = ({issues, children}) => {
  const hasAlerts = issues.alerts.length > 0;
  const hasWarnings = issues.warnings.length > 0;
  return (
    <tr className={hasAlerts ? 'table-danger' : hasWarnings ? 'table-warning' : null}>
      {children}
    </tr>
  );
};

const Issue = ({issue}) => (
  <OverlayTrigger overlay={
    <Popover id="issue-popover">
      <Popover.Title as="h3">{issue.name}</Popover.Title>
      <Popover.Content>{issue.description}</Popover.Content>
    </Popover>
  }>
    <svg width="1.0625em" height="1em" viewBox="0 0 17 16" className="bi bi-exclamation-triangle-fill text-danger" fill="currentColor" xmlns="http:www.w3.org/2000/svg">
      <path fillRule="evenodd" d="M8.982 1.566a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767L8.982 1.566zM8 5a.905.905 0 0 0-.9.995l.35 3.507a.552.552 0 0 0 1.1 0l.35-3.507A.905.905 0 0 0 8 5zm.002 6a1 1 0 1 0 0 2 1 1 0 0 0 0-2z"/>
    </svg>
  </OverlayTrigger>
);

export const Issues = ({issues}) => {
  return (
    <>
      {issues.alerts.map(i => <Issue issue={i} key={i}/>)}
      {issues.warnings.map(i => <Issue issue={i} key={i}/>)}
    </>
  );
}
