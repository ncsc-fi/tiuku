import {
  string,
  arrayOf,
  struct
} from '../../common/parser';

const mailboxForwarding = (context, x) => {
  const o = struct({
    DisplayName: string,
    UserPrincipalName: string,
    ForwardingAddress: string
  })(context, x);

  return {
    displayName: o.DisplayName,
    userPrincipalName: o.UserPrincipalName,
    forwardingAddress: o.ForwardingAddress
  };
};

const mailboxForwardingRules = arrayOf(mailboxForwarding);

export default mailboxForwardingRules;
