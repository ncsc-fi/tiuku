import {
  struct,
  number,
  groupObjectCounts
} from '../../common/parser';

const domainOverview = (context, x) => {
  const o = struct({
    UserCount: number,
    DomainAdminGroupUserCount: number,
    AdminCount1UserCount: number,
    GroupCount: number,
    ComputerCount: number,
    ComputerCountByOs: groupObjectCounts,
    ForestDomainCount: number,
    OrganizationalUnitCount: number
  })(context, x);

  return {
    userCount: o.UserCount,
    domainAdminGroupUserCount: o.DomainAdminGroupUserCount,
    adminCount1UserCount: o.AdminCount1UserCount,
    groupCount: o.GroupCount,
    computerCount: o.ComputerCount,
    computerCountByOs: o.ComputerCountByOs,
    forestDomainCount: o.ForestDomainCount,
    organizationalUnitCount: o.OrganizationalUnitCount
  };
};

export default domainOverview;
