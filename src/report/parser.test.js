import * as ReportType from './ReportType';
import {
  reportType,
  parseReport
} from './parser';

describe('reportType', () => {
  it('throws an exception if the input is invalid', () => {
    const context = 'some.context';
    const input = 'LOL';
    expect(() => {
      reportType(context, input);
    }).toThrow();
  });

  it('returns valid report types as-is', () => {
    const context = 'some.context';
    const input = ReportType.M365;
    const result = reportType(context, input);
    expect(result).toEqual(input);
  });

  it('returns ReportType.M365 if the report type is undefined', () => {
    const context = 'some.context';
    const input = undefined;
    const result = reportType(context, input);
    expect(result).toEqual(ReportType.M365);
  });
});

// The following tests are only used to check that all of the parsing code is
// wired together by passing it a single happy-case input document. Use
// parser-specific tests (like the ones above) for more thorough testing with
// various inputs.

const validAdReportDoc = {
  ReportType: ReportType.AD,
  PasswordPolicy: {
    MinPasswordLength: 8,
    PasswordHistoryCount: 24,
    ComplexityEnabled: true,
    ReversibleEncryptionEnabled: false,
    LockoutThreshold: 0,
    LockoutDuration: {
      TotalMinutes: 30
    },
    LockoutObservationWindow: {
      TotalMinutes: 20
    }
  },
  DomainAdmins: [
    {
      GroupDomain: "hunter.lab",
      GroupName: "Domain Admins",
      GroupDistinguishedName: "CN=Domain Admins,CN=Users,DC=hunter,DC=lab",
      MemberDomain: "hunter.lab",
      MemberName: "hunter",
      MemberDistinguishedName: "CN=hunter,CN=Users,DC=hunter,DC=lab",
      MemberObjectClass: "user",
      MemberSID: "S-1-5-21-2788111761-1557451326-2546827300-500"
    }
  ],
  DomainOverview: {
    OrganizationalUnitCount: 1,
    AdminCount1UserCount: 2,
    ForestDomainCount: 1,
    GroupCount: 49,
    ComputerCountByOs: [
      {
        Values: [
          "Windows Server 2019 Datacenter"
        ],
        Count: 1,
        Group: [],
        Name: "Windows Server 2019 Datacenter"
      },
      {
        Values: [
          "Windows 10 Pro N"
        ],
        Count: 2,
        Group: [],
        Name: "Windows 10 Pro N"
      }
    ],
    ComputerCount: 3,
    UserCount: 13,
    DomainAdminGroupUserCount: 1
  },
  KrbtgtUsers: [
    {
      Domain: 'hunter.lab',
      User: {
        Name: 'krbtgt',
        Created: '/Date(1608198300000)/',
        PasswordLastSet: '/Date(1608198300526)/',
        'msDS-KeyVersionNumber': 2,
        'msDS-KrbTgtLinkBl': []
      },
    }
  ]
}

describe('parseReport', () => {
  it('can parse M365 reports', () => {
    const reportDoc = {
      Users: [
        {
          DisplayName: 'Alice',
          UserPrincipalName: 'alice@example.com',
          StrongAuthenticationRequirements: [{State: 'Disabled'}]
        },
        {
          DisplayName: 'Bob',
          UserPrincipalName: 'bob@example.com',
          StrongAuthenticationRequirements: [{State: 'Enabled'}]
        },
        {
          DisplayName: 'Eve',
          UserPrincipalName: 'eve@example.com',
          // No permission to read the data
          StrongAuthenticationRequirements: null
        },
        {
          DisplayName: 'Mallory',
          UserPrincipalName: 'mallory@example.com',
          StrongAuthenticationRequirements: []
        }
      ],
      Mailboxes: [
        {
          'DisplayName': 'Box1',
          'UserPrincipalName': 'principal1@example.com',
          'AuditEnabled': false,
          'DefaultAuditSet': ['Admin', 'Delegate', 'Owner']
        },
        {
          'DisplayName': 'Box2',
          'UserPrincipalName': 'principal2@example.com',
          'AuditEnabled': true,
          'DefaultAuditSet': ['Owner']
        }
      ],
      Globaladmins: [
        {
          'DisplayName': 'Bob',
          'UserPrincipalName': 'bob@example.com'
        }
      ],
      AzureDNSRecords: [
        {
          Id: "/subscriptions/d36facf8-e23f-44f1-3afd-b81855a499ce/resourceGroups/ad-hunting-lab/providers/Microsoft.Network/dnszones/example.com/NS/@",
          Name: "@",
          ZoneName: "example.com",
          ResourceGroupName: "ad-hunting-lab",
          Ttl: 172800,
          "Etag": "5d1dcb31-1bc1-4531-bf4d-fb80edf3829a",
          "RecordType": 5,
          "TargetResourceId": null,
          "Records": [
            {
              Nsdname: "ns1-09.azure-dns.com."
            },
            {
              Nsdname: "ns2-09.azure-dns.net."
            },
            {
              Nsdname: "ns3-09.azure-dns.org."
            },
            {
              Nsdname: "ns4-09.azure-dns.info."
            }
          ],
          Metadata: null,
          ProvisioningState: "Succeeded"
        }
      ],
      MailboxForwardingRules: [
        {
          'DisplayName': 'Box1',
          'UserPrincipalName': 'principal1@example.com',
          'ForwardingAddress': 'testing@example.com'
        },
      ],
    };
    const report = JSON.stringify(reportDoc);
    const result = parseReport(report);
    expect(result).toEqual({
      reportType: ReportType.M365,
      users: [
        {
          displayName: 'Alice',
          userPrincipalName: 'alice@example.com',
          mfaState: 'Disabled'
        },
        {
          displayName: 'Bob',
          userPrincipalName: 'bob@example.com',
          mfaState: 'Enabled'
        },
        {
          displayName: 'Eve',
          userPrincipalName: 'eve@example.com',
          mfaState: null
        },
        {
          displayName: 'Mallory',
          userPrincipalName: 'mallory@example.com',
          mfaState: 'Disabled'
        }
      ],
      mailboxes: [
        {
          displayName: 'Box1',
          userPrincipalName: 'principal1@example.com',
          isAuditEnabled: false,
          defaultAuditSet: ['Admin', 'Delegate', 'Owner']
        },
        {
          displayName: 'Box2',
          userPrincipalName: 'principal2@example.com',
          isAuditEnabled: true,
          defaultAuditSet: ['Owner']
        }
      ],
      globalAdmins: [
        {
          displayName: 'Bob',
          userPrincipalName: 'bob@example.com'
        }
      ],
      dnsRecords: [
        {
          name: "@",
          zoneName: "example.com",
          recordType: 'NS',
          records: [
            {
              Nsdname: 'ns1-09.azure-dns.com.'
            },
            {
              Nsdname: 'ns2-09.azure-dns.net.'
            },
            {
              Nsdname: 'ns3-09.azure-dns.org.'
            },
            {
              Nsdname: 'ns4-09.azure-dns.info.'
            }
          ]
        }
      ],
      mailboxForwardingRules: [
        {
          displayName: 'Box1',
          userPrincipalName: 'principal1@example.com',
          forwardingAddress: 'testing@example.com'
        }
      ]
    });
  });

  
  it('can parse AD reports', () => {
    const reportDoc = {
      ReportType: ReportType.AD,
      PasswordPolicy: {
        MinPasswordLength: 8,
        PasswordHistoryCount: 24,
        ComplexityEnabled: true,
        ReversibleEncryptionEnabled: false,
        LockoutThreshold: 0,
        LockoutDuration: {
          TotalMinutes: 30
        },
        LockoutObservationWindow: {
          TotalMinutes: 20
        }
      },
      DomainAdmins: [
        {
          GroupDomain: "hunter.lab",
          GroupName: "Domain Admins",
          GroupDistinguishedName: "CN=Domain Admins,CN=Users,DC=hunter,DC=lab",
          MemberDomain: "hunter.lab",
          MemberName: "hunter",
          MemberDistinguishedName: "CN=hunter,CN=Users,DC=hunter,DC=lab",
          MemberObjectClass: "user",
          MemberSID: "S-1-5-21-2788111761-1557451326-2546827300-500"
        }
      ],
      DomainOverview: {
        OrganizationalUnitCount: 1,
        AdminCount1UserCount: 2,
        ForestDomainCount: 1,
        GroupCount: 49,
        ComputerCountByOs: [
          {
            Values: [
              "Windows Server 2019 Datacenter"
            ],
            Count: 1,
            Group: [],
            Name: "Windows Server 2019 Datacenter"
          },
          {
            Values: [
              "Windows 10 Pro N"
            ],
            Count: 2,
            Group: [],
            Name: "Windows 10 Pro N"
          }
        ],
        ComputerCount: 3,
        UserCount: 13,
        DomainAdminGroupUserCount: 1
      },
      KrbtgtUsers: [
        {
          Domain: 'hunter.lab',
          User: {
            Name: 'krbtgt',
            Created: '/Date(1608198300000)/',
            PasswordLastSet: '/Date(1608198300526)/',
            'msDS-KeyVersionNumber': 2,
            'msDS-KrbTgtLinkBl': []
          },
        }
      ]
    };
    const report = JSON.stringify(reportDoc);
    const result = parseReport(report);
    expect(result).toEqual({
      reportType: ReportType.AD,
      passwordPolicy: {
        minLength: {
          value: 8
        },
        historySize: {
          value: 24
        },
        complexityCheckEnabled: {
          value: true
        },
        reversibleEncryptionEnabled: {
          value: false
        },
        lockout: {
          threshold: {
            value: 0
          },
          duration: {
            value: 30
          },
          resetCounterAfter: {
            value: 20
          }
        }
      },
      domainAdmins: [
        {
          groupDomain: "hunter.lab",
          groupName: "Domain Admins",
          memberDistinguishedName: "CN=hunter,CN=Users,DC=hunter,DC=lab",
          memberDomain: "hunter.lab",
          memberName: "hunter"
        }
      ],
      domainOverview: {
        userCount: 13,
        domainAdminGroupUserCount: 1,
        adminCount1UserCount: 2,
        groupCount: 49,
        computerCount: 3,
        computerCountByOs: {
          'Windows Server 2019 Datacenter': 1,
          'Windows 10 Pro N': 2
        },
        forestDomainCount: 1,
        organizationalUnitCount: 1
      },
      krbtgtUsers: [
        {
          domain: 'hunter.lab',
          name: 'krbtgt',
          keyVersionNumber: 2,
          created: new Date(Date.parse('2020-12-17T09:45:00.000Z')),
          passwordChanged: new Date(Date.parse('2020-12-17T09:45:00.526Z'))
        }
      ]
    });
  });

  it('can parse report with null PasswordPolicy', () => {
    const reportDoc = {
      ...validAdReportDoc,
      PasswordPolicy: null
    };
    const report = JSON.stringify(reportDoc);
    const result = parseReport(report);
    expect(result.passwordPolicy).toBeNull();
  });
});
