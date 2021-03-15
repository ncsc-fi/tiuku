import {
  string,
  arrayOf,
  number,
  struct,
} from '../../common/parser';

const superuser = (context, x) => {

  const o = struct({
    Username: string,
    GroupId: number,
    UserId: number,
    Shell: string
  })(context, x);

  return {
    username: o.Username,
    groupId: o.GroupId,
    userId: o.UserId,
    shell: o.Shell
  };
};

const superusers = arrayOf(superuser);

export default superusers;
