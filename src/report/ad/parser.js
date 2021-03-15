import {struct, maybe} from '../common/parser';
import passwordPolicy from './passwordPolicy/parser';
import domainAdmins from './domainAdmins/parser';
import domainOverview from './domainOverview/parser';
import krbtgtUsers from './krbtgtUsers/parser';

const report = (context, x) => {
  const o = struct({
    PasswordPolicy: maybe(passwordPolicy),
    DomainAdmins: domainAdmins,
    DomainOverview: domainOverview,
    KrbtgtUsers: krbtgtUsers
  })(context, x);

  return {
    passwordPolicy: o.PasswordPolicy,
    domainAdmins: o.DomainAdmins,
    domainOverview: o.DomainOverview,
    krbtgtUsers: o.KrbtgtUsers
  };
};

export default report;
