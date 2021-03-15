import {propertyMapper} from '../common/analyzer';
import analyzeUsers from './users/analyzer';

const analyze = propertyMapper({
  users: analyzeUsers
});

export default analyze;
