import * as ReportType from './ReportType';
import analyzeAd from './ad/analyzer';
import analyzeM365 from './m365/analyzer';
import analyzeLinux from './linux/analyzer';

export const analyzeReport = (report) => {
  if (report.reportType === ReportType.M365) {
    return analyzeM365(report);
  } else if (report.reportType === ReportType.LINUX)  {
    return analyzeLinux(report)
  } else {
    return analyzeAd(report);
  }
};
