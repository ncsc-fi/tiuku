import {propertyMapper} from '../common/analyzer';
import analyzePasswordPolicy from './passwordPolicy/analyzer';
import analyzeKrbtgtUsers from './krbtgtUsers/analyzer';

const analyze = propertyMapper({
  passwordPolicy: x => x ? analyzePasswordPolicy(x) : x,
  krbtgtUsers: analyzeKrbtgtUsers
});

export default analyze;
