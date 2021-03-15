import {
  string,
  arrayOf,
  struct,
  enum_,
  maybe,
} from '../../common/parser';

const mfaState = enum_('Enabled', 'Disabled', 'Enforced');

const strongAuthenticationRequirement = (context, x) => {
  const o = struct({State: mfaState})(context, x);
  return {
    mfaState: o.State
  };
};

export const strongAuthenticationRequirements = (context, x) => {
  const a = arrayOf(strongAuthenticationRequirement)(context, x);
  if (a.length > 0) {
    return a[0];
  } else {
    return {
      mfaState: 'Disabled'
    };
  }
};

const user = (context, x) => {
  const o = struct({
    DisplayName: string,
    UserPrincipalName: string,
    StrongAuthenticationRequirements: maybe(strongAuthenticationRequirements)
  })(context, x);

  return {
    displayName: o.DisplayName,
    userPrincipalName: o.UserPrincipalName,
    mfaState: o.StrongAuthenticationRequirements && o.StrongAuthenticationRequirements.mfaState
  };
};

const users = arrayOf(user);

export default users;
