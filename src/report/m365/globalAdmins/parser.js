import {
  string,
  arrayOf,
  struct
} from '../../common/parser';

const globalAdmin = (context, x) => {
  const o = struct({
    DisplayName: string,
    UserPrincipalName: string,
  })(context, x);

  return {
    displayName: o.DisplayName,
    userPrincipalName: o.UserPrincipalName,
  };
};

const globalAdmins = arrayOf(globalAdmin);

export default globalAdmins;
