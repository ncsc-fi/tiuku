import {
  arrayOf,
  netTimestamp,
  number,
  struct,
  string
} from '../../common/parser';

const krbtgtUser = (context, x) => {
  const o = struct({
    Domain: string,
    User: struct({
      Name: string,
      'msDS-KeyVersionNumber': number,
      Created: netTimestamp,
      PasswordLastSet: netTimestamp
    })
  })(context, x);

  return {
    domain: o.Domain,
    name: o.User.Name,
    keyVersionNumber: o.User['msDS-KeyVersionNumber'],
    created: o.User.Created,
    passwordChanged: o.User.PasswordLastSet
  };
};

const krbtgtUsers = arrayOf(krbtgtUser);

export default krbtgtUsers;
