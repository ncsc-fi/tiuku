import {struct} from '../common/parser';
import users from './users/parser';
import mailboxes from './mailboxes/parser';
import globalAdmins from './globalAdmins/parser';
import dnsRecords from './dnsRecords/parser';
import mailboxForwardingRules from './mailbox-forwardingrules/parser';

const report = (context, x) => {
  const o = struct({
    Users: users,
    Mailboxes: mailboxes,
    Globaladmins: globalAdmins,
    AzureDNSRecords: dnsRecords,
    MailboxForwardingRules: mailboxForwardingRules
  })(context, x);

  return {
    users: o.Users,
    mailboxes: o.Mailboxes,
    globalAdmins: o.Globaladmins,
    dnsRecords: o.AzureDNSRecords,
    mailboxForwardingRules: o.MailboxForwardingRules
  };
};

export default report;
