import Container from 'react-bootstrap/Container';
import Row from 'react-bootstrap/Row';
import Col from 'react-bootstrap/Col';
import Users from './users/ui';
import Mailboxes from './mailboxes/ui';
import Globaladmins from './globalAdmins/ui';
import Dnsrecords from './dnsRecords/ui';
import MailboxesForwardingRules from './mailbox-forwardingrules/ui';

const ReportM365 = ({report}) => (
  <div>
    <Container className="mt-3">
      <Row>
        <Col>
          <Users users={report.users}/>
        </Col>
      </Row>
    </Container>

    <Container className="mt-3">
      <Row>
        <Col>
          <Mailboxes mailboxes={report.mailboxes}/>
        </Col>
      </Row>
    </Container>
    <Container className="mt-3">
      <Row>
        <Col>
          <Globaladmins globalAdmins={report.globalAdmins}/>
        </Col>
      </Row>
    </Container>
    <Container className="mt-3">
      <Row>
        <Col>
          <Dnsrecords dnsRecords={report.dnsRecords}/>
        </Col>
      </Row>
    </Container>
    <Container className="mt-3">
      <Row>
        <Col>
          <MailboxesForwardingRules mailboxForwarding={report.mailboxForwardingRules}/>
        </Col>
      </Row>
    </Container>
  </div>
);

export default ReportM365;
