# Copyright 2019 Splunk, Inc.
#
# Use of this source code is governed by a BSD-2-clause-style
# license that can be found in the LICENSE-BSD2 file or at
# https://opensource.org/licenses/BSD-2-Clause

from jinja2 import Environment, select_autoescape

from .sendmessage import sendsingle
from .splunkutils import  splunk_single
from .timeutils import time_operations
import datetime
import pytest

env = Environment(autoescape=select_autoescape(default_for_string=False))

epic_ehr_testdata = [r'{{ mark }} {{ iso }}Z {{ host }} Epic 7652 - [origin software="Security-SIEM" swVersion="10.5.0"] <?xml version="1.0"?><EventLog>    <E1Mid>IC_SERVICE_AUDIT</E1Mid>    <EventCnt>1</EventCnt>    <EMPid>113^SERVICE, INTERCONNECT^ICSVC</EMPid>    <Source>poc</Source>    <LWSid></LWSid>    <Action>Query</Action>    <Date>1/19/2024</Date>    <Time>10:43:19 AM</Time>    <Flag>Access History^^</Flag>    <Mnemonics>      <Mnemonic Name="APIID">        <Value>000000000008C6E0FF7E77B293A3D24E</Value>      </Mnemonic>      <Mnemonic Name="APPLICATIONID">        <Value>020BB1F792114DDA872E791675ABCDEF</Value>      </Mnemonic>      <Mnemonic Name="CLIENTNAME">        <Value>TST-EPIC-CEW4</Value>      </Mnemonic>      <Mnemonic Name="INSTANCEURN">        <Value>urn:Emory:CE-POC-DI</Value>      </Mnemonic>      <Mnemonic Name="IP">        <Value>Unknown IP</Value>      </Mnemonic>      <Mnemonic Name="SERVICECATEGORY">        <Value>Interconnect</Value>      </Mnemonic>      <Mnemonic Name="SERVICEID">        <Value>b845c2d6-cfb7-492e-8f2a-cf35d6604bff</Value>      </Mnemonic>      <Mnemonic Name="SERVICENAME">        <Value>urn:epic-com:Interconnect.2019.Services.Diagnostics.StatusOverview</Value>      </Mnemonic>      <Mnemonic Name="SERVICETYPE">        <Value>REST-WebAPI</Value>      </Mnemonic>    </Mnemonics>  </EventLog>',]

@pytest.mark.parametrize("event", epic_ehr_testdata)
@pytest.mark.addons("epic")
def test_epic_ehr(
    record_property, get_host_key, setup_splunk, setup_sc4s, event
):
    host = get_host_key

    dt = datetime.datetime.now(datetime.timezone.utc)
    iso, _, _, _, _, _, epoch = time_operations(dt)

    # Tune time functions
    iso = dt.isoformat()[0:23]
    epoch = epoch[:-3]

    mt = env.from_string(event + "\n")
    message = mt.render(mark="<85>1", iso=iso, host=host)

    sendsingle(message, setup_sc4s[0], setup_sc4s[1][514])

    st = env.from_string(
        'search _time={{ epoch }} index=main host="{{ host }}" sourcetype="epic:epic_ehr:syslog" source="epic_ehr"'
    )
    search = st.render(epoch=epoch, host=host)

    result_count, _ = splunk_single(setup_splunk, search)

    record_property("host", host)
    record_property("resultCount", result_count)
    record_property("message", message)

    assert result_count == 1

