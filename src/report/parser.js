import * as ReportType from './ReportType';
import {
  emptyContext,
  json,
  struct,
  enum_
} from './common/parser';
import reportAd from './ad/parser.js';
import reportM365 from './m365/parser.js';
import reportLinux from './linux/parser.js';

const reportTypeEnum = enum_(ReportType.M365, ReportType.AD, ReportType.LINUX);

export const reportType = (context, x) => {
  if (x === undefined) {
    return ReportType.M365;
  }
  return reportTypeEnum(context, x);
};

export const parseReport = (x) => {
  const context = emptyContext;
  const doc = json(context, x);

  const o = struct({
    ReportType: reportType,
  })(context, doc);

  let report;
  if (o.ReportType === ReportType.M365) {
    report = reportM365(context, doc);
  } else if (o.ReportType === ReportType.AD) {
    report = reportAd(context, doc);
  } else if (o.ReportType === ReportType.LINUX) {
    report = reportLinux(context, doc);
  }

  return {
    ...report,
    reportType: o.ReportType
  };
};
