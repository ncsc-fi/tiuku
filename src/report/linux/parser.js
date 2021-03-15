import {struct} from '../common/parser';
import superusers from './superusers/parser'

const report = (context, x) => {
  const o = struct({
    Superusers: superusers,
  })(context, x);

  return {
    superusers: o.Superusers,
  };
};

export default report;
