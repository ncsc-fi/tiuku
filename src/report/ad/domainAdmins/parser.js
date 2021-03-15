import {
  arrayOf,
  struct,
  string
} from '../../common/parser';

const domainAdmin = (context, x) => {
  const o = struct({
    GroupDomain: string,
    GroupName: string,
    MemberDomain: string,
    MemberName: string,
    MemberDistinguishedName: string
  })(context, x);

  return {
    groupDomain: o.GroupDomain,
    groupName: o.GroupName,
    memberDomain: o.MemberDomain,
    memberName: o.MemberName,
    memberDistinguishedName: o.MemberDistinguishedName
  };
};

const domainAdmins = arrayOf(domainAdmin);

export default domainAdmins;
