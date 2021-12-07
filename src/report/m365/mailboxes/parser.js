import {
  string,
  boolean,
  arrayOf,
  struct,
  maybe
} from '../../common/parser';

const mailbox = (context, x) => {
  const o = struct({
    DisplayName: string,
    UserPrincipalName: string,
    AuditEnabled: maybe(boolean),
    DefaultAuditSet: maybe(arrayOf(string))
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
