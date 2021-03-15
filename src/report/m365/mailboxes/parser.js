import {
  string,
  boolean,
  arrayOf,
  struct
} from '../../common/parser';

const mailbox = (context, x) => {
  const o = struct({
    DisplayName: string,
    UserPrincipalName: string,
    AuditEnabled: boolean,
    DefaultAuditSet: arrayOf(string)
  })(context, x);

  return {
    displayName: o.DisplayName,
    userPrincipalName: o.UserPrincipalName,
    isAuditEnabled: o.AuditEnabled,
    defaultAuditSet: o.DefaultAuditSet
  };
};

const mailboxes = arrayOf(mailbox);

export default mailboxes;
