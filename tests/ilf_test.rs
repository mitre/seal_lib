/**
 * Copyright 2025 The MITRE Corporation

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */

use seal_lib::{parse_log_to_tuple, parse_logs, Log, Numeric, Value::*};
use std::{collections::HashMap, fs};

#[test]
fn parse_match_log() {
    let hbl1 = "_hblMatch[1,1,,(matchingIndices=[0,40];length=40;)] start[c1,c3,1234,(c.c1.v1=3;_hblID=0;)] ";
    is_ilf_parsable(hbl1);
}

#[test]
fn log() {
    let str = " m1[c1,c2,1, ] ";
    compare_ilf(str, "m1", "c1", "c2", "1", vec![], vec![]);

    let str2 = " m1[c1,c2,1,(var1=1;)] ";
    compare_ilf(str2, "m1", "c1", "c2", "1", vec![], vec![("var1", "1")]);
}

#[test]
fn no_value() {
    let str = " m1[c1,c2,1,(var1=;)] ";
    is_ilf_parsable(str);
}

#[test]
fn write_log_test() {
    let attrs_values = vec![
        (
            "val_double",
            "val_double=3.1;",
            VNum(Numeric::Double(ordered_float::OrderedFloat(3.1))),
        ),
        ("val_int", "val_int=1;", VNum(Numeric::Int(1))),
        (
            "val_str",
            r#"val_str="with /\\\\\\ \\\" ''\"\" \\t \\n weird escaping _!@#$%^&*(""#,
            VString(r#"with /\\\ \" ''"" \t \n weird escaping _!@#$%^&*("#.to_string()),
        ),
        ("val_boolean", "val_boolean=true;", VBoolean(true)),
        (
            "val_array",
            "val_array=[1,3.1];",
            VArray(vec![
                Numeric::Int(1),
                Numeric::Double(ordered_float::OrderedFloat(3.1)),
            ]),
        ),
        (
            "val_long",
            "val_long=2147483648;",
            VNum(Numeric::Long((i32::MAX as i64) + 1)),
        ),
        ("val_none", "val_none=;", VNone),
    ];

    let mut attrs = HashMap::new();
    for (name, _, val) in attrs_values.iter() {
        attrs.insert(name.to_string(), val.clone());
    }

    let log = Log {
        log_type: "m1".into(),
        src: "c1".into(),
        dest: "c2".into(),
        timestamp: "1".into(),
        fields: vec![],
        attributes: attrs,
    };

    let res = log.to_string();

    // We don't know the order that this will be serialized in so we have to check that the string contains the appropriate output somewhere
    let start = "m1[c1,c2,1,(";
    let end = ")] ";

    assert!(res.starts_with(start));
    assert!(res.ends_with(end));

    for (name, str, _) in attrs_values.iter() {
        assert!(
            res.contains(str),
            "attr {} not found in ILF \"{}\". Expected {}",
            name,
            res,
            str
        )
    }
}

#[test]
fn tuple_parse() {
    // Based on caldera plugin ILF
    let str = r#"fact_add_callback[*,*,1666203523,(metadata__timestamp=1666203522.895246;fact__relationships__0="domain.user.name(root)";)] "#;
    compare_ilf(
        str,
        "fact_add_callback",
        "*",
        "*",
        "1666203523",
        vec![],
        vec![
            ("metadata__timestamp", "1666203522.895246"),
            ("fact__relationships__0", r#""domain.user.name(root)""#),
        ],
    )
}

#[test]
fn empty_timestamp() {
    let str = "audit[*,*,,(type=\"SYSCALL\";)] ";
    compare_ilf(
        str,
        "audit",
        "*",
        "*",
        "",
        vec![],
        vec![("type", "SYSCALL")],
    );
}

#[test]
fn chinese_in_ilf() {
    is_ilf_parsable(r#"a[*,*,,(a="chinese: 𡨸漢𡨸儒")] "#);
    is_ilf_parsable(r#"a[*,*,,(a="Hiragana: の, は, でした")] "#);
    is_ilf_parsable(r#"a[*,*,,(a="Katakana: コンサート")] "#);
    is_ilf_parsable(r#"a[*,*,,(a="Kanji: 昨夜, 最高")] "#);
}

// TODO: test that whitespace between ILF is allowed/ignored

#[test]
fn hex_in_ilf() {
    let str = r#"ZeekFiles[*,*,1649964738.649337,(tx_hosts="{\x0a\x0948.0.0.2\x0a}";rx_hosts="{\x0a\x0916.0.0.2\x0a}";conn_uids="{\x0aCzsBT31pBQyS41q0Na\x0a}";analyzers="{\x0a\x0a}")] "#;
    compare_ilf(
        str,
        "ZeekFiles",
        "*",
        "*",
        "1649964738.649337",
        vec![],
        vec![
            ("tx_hosts", r#""{\\x0a\\x0948.0.0.2\\x0a}""#),
            ("rx_hosts", r#""{\\x0a\\x0916.0.0.2\\x0a}""#),
            ("conn_uids", r#""{\\x0aCzsBT31pBQyS41q0Na\\x0a}""#),
            ("analyzers", r#""{\\x0a\\x0a}""#),
        ],
    )
}

#[test]
fn special_numbers_in_ilf() {
    let str = r#"a[*,*,0,(num1=0xDEADBEEF; num2=0o10; num3=0b10; num4=-12.3e-4)] "#;
    compare_ilf(
        str,
        "a",
        "*",
        "*",
        "0",
        vec![],
        vec![
            ("num1", "3735928559"),
            ("num2", "8"),
            ("num3", "2"),
            ("num4", "-0.00123"),
        ],
    )
}

#[test]
fn stack_overflow() {
    let ilf = r##"agent_response_event[*,*,1681141948,(agent__architecture="amd64";agent__trusted=True;agent__last_seen="2023-04-10T15:52:28Z";agent__host_ip_addrs__0="10.206.96.199";agent__location="C:\\Users\\Public\\splunkd.exe";agent__ppid=8184;agent__created="2023-03-30T13:34:38Z";agent__username="DESKTOP-B849NTP\\Army";agent__sleep_min=30;agent__platform="windows";agent__links__0__visibility__score=50;agent__links__0__finish="2023-03-30T13:34:39Z";agent__links__0__output="False";agent__links__0__status=0;agent__links__0__jitter=0;agent__links__0__deadman=False;agent__links__0__plaintext_command="Q2xlYXItSGlzdG9yeTtDbGVhcg==";agent__links__0__executor__timeout=60;agent__links__0__executor__platform="windows";agent__links__0__executor__name="psh";agent__links__0__executor__command="Clear-History;Clear";agent__links__0__cleanup=0;agent__links__0__paw="gqfrrj";agent__links__0__ability__technique_name="Indicator Removal on Host: Clear Command History";agent__links__0__ability__delete_payload=True;)] "##;
    let smaller_ilf = r##"agent_response_event[*,*,1681141948,(agent__architecture="amd64";agent__trusted=True;agent__last_seen="2023-04-10T15:52:28Z";agent__host_ip_addrs__0="10.206.96.199";agent__location="C:\\Users\\Public\\splunkd.exe";agent__ppid=8184;agent__created="2023-03-30T13:34:38Z";agent__username="DESKTOP-B849NTP\\Army";agent__sleep_min=30;agent__platform="windows";agent__links__0__visibility__score=50;agent__links__0__finish="2023-03-30T13:34:39Z";agent__links__0__output="False";agent__links__0__status=0;agent__links__0__jitter=0;agent__links__0__deadman=False;agent__links__0__plaintext_command="Q2xlYXItSGlzdG9yeTtDbGVhcg==";agent__links__0__executor__timeout=60;agent__links__0__executor__platform="windows";agent__links__0__executor__name="psh";agent__links__0__executor__command="Clear-History;Clear";agent__links__0__cleanup=0;agent__links__0__paw="gqfrrj";agent__links__0__ability__technique_name="Indicator Removal on Host: Clear Command History";)]  "##;
    is_ilf_parsable(ilf);
    is_ilf_parsable(smaller_ilf);
}

#[test]
#[should_panic]
fn no_timestamp() {
    let str = r#"m1[c1,c3, (c.c1.v1 = 3;eth_type = 0x46;)] "#;
    compare_ilf(str, "m1", "c1", "c3", "", vec![], vec![])
}

#[test]
fn number_without_semicolon_delimiter() {
    let str = r#"a[*,*,2,(num=1)] "#;
    compare_ilf(str, "a", "*", "*", "2", vec![], vec![("num", "1")]);
}

#[test]
fn array_with_numbers() {
    let str = r#"a[*,*,2,(num=[-1,+5.3,0x10])] "#;
    compare_ilf(
        str,
        "a",
        "*",
        "*",
        "2",
        vec![],
        vec![("num", "[-1,+5.3,16]")],
    );
}

// Supposed to fail
// #[test]
// fn test_weird_one() {
//     let str = r#"ThreadRemoteCreate[*,*,2021-03-25T15:40:00.000Z,(host_name=“localhost”; thread_start_function=“test LoadLibraryW test”; user_name=“admin”; process_id=500; thread_id=120; target_process_id=510; thread_new_id=125)] "#;
//     is_ilf_parsable(str);
// }

#[test]
fn square_bracket_in_string() {
    let str = r#"a[*,*,2,(str="hello [ hel]lo ] ")] "#;
    is_ilf_parsable(str);
}

#[test]
fn string_starting_with_number() {
    let str = r#"ZeekFiles[*,*,1649964738.649337,(duration="108.0 msecs 389.854431 usecs";)] "#;
    compare_ilf(
        str,
        "ZeekFiles",
        "*",
        "*",
        "1649964738.649337",
        vec![],
        vec![("duration", "\"108.0 msecs 389.854431 usecs\"")],
    );
}

#[test]
fn ilf_from_ocsf() {
    let str = r#"default_name[*,*,2024-11-15T11:36:42.066471-05:00,(unmapped.responseObject.status.nodeInfo.operatingSystem="linux";type_name="API Activity: Create";actor.session.created_time_dt=;actor.user.groups.1.desc=;end_time_dt=;observables.0.type_id=4;actor.session.credential_uid="EXAMPLEUIDTEST";src_endpoint.ip="12.000.22.33";src_endpoint.os=;unmapped.requestObject.status.addresses.1.type="ExternalIP";actor.user.ldap_person=;api.request.data=;observables.1.reputation=;api.service=;src_endpoint.type_=;src_endpoint.proxy_endpoint=;unmapped.responseObject.status.conditions.1.type="DiskPressure";resources.0.criticality=;api.response.data=;http_request.length=;unmapped.requestObject.status.conditions.1.lastHeartbeatTime="2021-09-07T20:37:28Z";actor.user.risk_level=;actor.app_name=;http_request.http_method=;http_request.url.path="/api/v1/nodes";class_uid=6003;src_endpoint.type_id=;unmapped.responseObject.metadata.labels.topology.kubernetes.io/zone="us-east-1f";unmapped.requestObject.metadata.labels.beta.kubernetes.io/os="linux";unmapped.requestObject.status.addresses.4.type="ExternalDNS";unmapped.responseObject.metadata.labels.eks.amazonaws.com/sourceLaunchTemplateId="lt-0f20d6f901007611e";unmapped.responseObject.spec.taints.0.effect="NoSchedule";class_name="API Activity";actor.user.groups.1.name="system:nodes";unmapped.requestObject.spec.providerID="aws:///us-east-1f/i-12345678901";unmapped.responseObject.metadata.labels.failure-domain.beta.kubernetes.io/region="us-east-1";status_code=;status_id=;unmapped.responseObject.status.addresses.3.address="ip-192-001-02-03.ec2.internal";unmapped.responseObject.apiVersion="v1";unmapped.annotations.authorization.k8s.io/reason="";unmapped.requestObject.status.addresses.4.address="ec2-12.000.22.33.compute-1.amazonaws.com";unmapped.requestObject.status.conditions.3.status="False";unmapped.requestObject.status.allocatable.hugepages-1Gi="0";actor.session.terminal=;unmapped.requestObject.metadata.labels.alpha.eksctl.io/nodegroup-name="ng-5fe434eb";unmapped.responseObject.metadata.managedFields.0.apiVersion="v1";unmapped.responseObject.metadata.labels.eks.amazonaws.com/nodegroup="ng-5fe434eb";unmapped.responseObject.status.conditions.2.reason="KubeletHasSufficientPID";unmapped.requestObject.status.allocatable.cpu="3920m";resources.0.uid=;unmapped.responseObject.metadata.labels.topology.kubernetes.io/region="us-east-1";unmapped.responseObject.status.nodeInfo.kubeProxyVersion="v1.21.2-eks-55daa9d";unmapped.responseObject.status.allocatable.memory="15076868Ki";metadata.log_name=;metadata.extension=;src_endpoint.port=;unmapped.requestObject.status.conditions.1.lastTransitionTime="2021-09-07T20:37:28Z";unmapped.requestObject.status.daemonEndpoints.kubeletEndpoint.Port=10250;actor.user.domain=;metadata.logged_time=;observables.0.value="system:node:ip-192-001-02-03.ec2.internal";unmapped.requestObject.status.conditions.1.status="False";http_request.version=;unmapped.requestObject.status.capacity.memory="16093700Ki";metadata.product.feature.version=;raw_data=;api.version="v1";actor.user.name="system:node:ip-192-001-02-03.ec2.internal";actor.user.type_=;metadata.log_level="RequestResponse";observables.1.type_="IP Address";unmapped.requestObject.status.addresses.0.address="192.000.22.33";unmapped.responseObject.metadata.labels.beta.kubernetes.io/arch="amd64";metadata.correlation_uid=;unmapped.responseObject.status.conditions.0.lastHeartbeatTime="2021-09-07T20:37:28Z";unmapped.responseObject.status.conditions.0.message="kubelet has sufficient memory available";unmapped.responseObject.status.nodeInfo.architecture="amd64";actor.session.expiration_reason=;metadata.product.version="audit.k8s.io/v1";unmapped.requestObject.status.addresses.3.address="ip-192-001-02-03.ec2.internal";unmapped.requestObject.metadata.labels.alpha.eksctl.io/cluster-name="ABCD1234567890EXAMPLE";status_detail=;unmapped.requestObject.metadata.labels.kubernetes.io/arch="amd64";unmapped.requestObject.status.conditions.2.reason="KubeletHasSufficientPID";unmapped.requestObject.metadata.labels.eks.amazonaws.com/nodegroup="ng-5fe434eb";observables.0.reputation=;src_endpoint.vlan_uid=;unmapped.requestObject.metadata.labels.eks.amazonaws.com/capacityType="ON_DEMAND";unmapped.requestObject.metadata.annotations.volumes.kubernetes.io/controller-managed-attach-detach="true";unmapped.responseObject.status.conditions.2.type="PIDPressure";metadata.product.feature.name="Elastic Kubernetes Service";resources.0.data=;unmapped.responseObject.status.conditions.1.lastTransitionTime="2021-09-07T20:37:28Z";actor.session.uid_alt=;cloud.account.type_id=;unmapped.requestObject.metadata.labels.kubernetes.io/hostname="ip-192-001-02-03.ec2.internal";unmapped.responseObject.status.conditions.2.status="False";api.group=;actor.session.issuer="arn:aws:iam::123456789012:role/example-test-161366663-NodeInstanceRole-abc12345678912";cloud.provider="AWS";metadata.data_classification=;unmapped.responseObject.status.nodeInfo.kubeletVersion="v1.21.2-eks-55daa9d";actor.user.groups.0.name="system:bootstrappers";metadata.product.cpe_name=;observables.1.name="src_endpoint.ip";unmapped.requestObject.status.allocatable.memory="15076868Ki";unmapped.requestObject.metadata.labels.eks.amazonaws.com/sourceLaunchTemplateVersion="1";actor.idp=;actor.user.groups.0.desc=;unmapped.responseObject.status.addresses.4.address="ec2-12.000.22.33.compute-1.amazonaws.com";unmapped.requestObject.status.conditions.2.type="PIDPressure";unmapped.requestObject.status.nodeInfo.kubeProxyVersion="v1.21.2-eks-55daa9d";metadata.event_code=;unmapped.responseObject.status.capacity.cpu="4";unmapped.responseObject.status.capacity.memory="16093700Ki";unmapped.requestObject.status.addresses.1.address="12.000.22.33";actor.user.risk_score=;cloud.org=;cloud.account.name=;unmapped.requestObject.status.nodeInfo.architecture="amd64";resources.0.region=;unmapped.requestObject.status.nodeInfo.bootID="0d0dd4f2-8829-4b03-9f29-794f4908281b";unmapped.requestObject.metadata.labels.topology.kubernetes.io/zone="us-east-1f";unmapped.responseObject.status.nodeInfo.osImage="Amazon Linux 2";actor.invoked_by=;actor.session.count=;resources.0.owner=;src_endpoint.interface_uid=;metadata.log_version=;unmapped.requestObject.status.nodeInfo.osImage="Amazon Linux 2";unmapped.responseObject.status.conditions.3.lastHeartbeatTime="2021-09-07T20:37:28Z";api.operation="create";src_endpoint.hw_info=;unmapped.responseObject.metadata.labels.failure-domain.beta.kubernetes.io/zone="us-east-1f";unmapped.responseObject.status.addresses.3.type="InternalDNS";actor.user.groups.0.type_=;duration=;actor.user.credential_uid=;timezone_offset=;unmapped.responseObject.metadata.labels.node.kubernetes.io/instance-type="m5.xlarge";unmapped.responseObject.status.conditions.0.status="False";unmapped.responseObject.status.conditions.2.lastHeartbeatTime="2021-09-07T20:37:28Z";actor.user.email_addr=;actor.app_uid=;unmapped.requestObject.status.capacity.cpu="4";src_endpoint.subnet_uid=;api.response.error_message=;observables.0.name="actor.user.name";message="ResponseComplete";metadata.sequence=;severity="Informational";src_endpoint.autonomous_system=;unmapped.requestObject.metadata.labels.beta.kubernetes.io/instance-type="m5.xlarge";activity_name="Create";src_endpoint.location=;unmapped.responseObject.metadata.uid="4ecf628a-1b50-47ed-932c-bb1df89dad10";unmapped.responseObject.metadata.managedFields.0.time="2021-09-07T20:37:30Z";type_uid=600301;metadata.product.path=;unmapped.responseObject.status.conditions.0.type="MemoryPressure";metadata.processed_time=;src_endpoint.svc_name=;unmapped.responseObject.status.conditions.3.lastTransitionTime="2021-09-07T20:37:28Z";unmapped.requestObject.status.addresses.2.address="ip-192-001-02-03.ec2.internal";unmapped.responseObject.status.conditions.1.status="False";actor.user.groups.2.name="system:authenticated";metadata.version="1.2.0";unmapped.responseObject.metadata.name="ip-192-001-02-03.ec2.internal";unmapped.responseObject.metadata.labels.kubernetes.io/arch="amd64";unmapped.responseObject.status.allocatable.hugepages-2Mi="0";unmapped.requestObject.status.conditions.3.type="Ready";unmapped.responseObject.metadata.managedFields.0.fieldsType="FieldsV1";unmapped.requestObject.status.nodeInfo.containerRuntimeVersion="docker://19.3.13";unmapped.requestObject.metadata.labels.node.kubernetes.io/instance-type="m5.xlarge";http_request.url.query_string=;unmapped.responseObject.kind="Node";actor.user.groups.1.uid=;unmapped.requestObject.metadata.labels.failure-domain.beta.kubernetes.io/zone="us-east-1f";unmapped.responseObject.status.conditions.3.status="False";unmapped.responseObject.status.nodeInfo.systemUUID="ec2483c6-33b0-e271-f36c-e14e45a361b8";time=1631047050642854;metadata.original_time=;observables.2.type_="URL String";unmapped.responseObject.metadata.managedFields.0.manager="kubelet";actor.user.account=;actor.user.risk_level_id=;status=;unmapped.requestObject.metadata.labels.topology.kubernetes.io/region="us-east-1";unmapped.annotations.authorization.k8s.io/decision="allow";resources.0.data_classification=;unmapped.requestObject.status.nodeInfo.systemUUID="ec2483c6-33b0-e271-f36c-e14e45a361b8";metadata.product.url_string=;resources.0.version=;http_request.url.url_string=;src_endpoint.container=;unmapped.requestObject.status.conditions.3.message="[container runtime status check may not have completed yet, container runtime network not ready: NetworkReady=false reason:NetworkPluginNotReady message:docker: network plugin is not ready: cni config uninitialized, CSINode is not yet initialized, missing node capacity for resources: ephemeral-storage]";actor.user.groups.2.uid=;observables.2.name="http_request.url.path";resources.0.group=;unmapped.requestObject.status.addresses.3.type="InternalDNS";actor.session.is_mfa=;actor.session.uid="i-12345678901";metadata.tenant_uid=;observables.1.type_id=2;unmapped.responseObject.metadata.labels.eks.amazonaws.com/capacityType="ON_DEMAND";unmapped.responseObject.status.allocatable.pods="58";actor.session.created_time=;unmapped.responseObject.status.conditions.2.message="kubelet has sufficient PID available";unmapped.responseObject.status.daemonEndpoints.kubeletEndpoint.Port=10250;metadata.processed_time_dt=;src_endpoint.owner=;unmapped.responseObject.status.capacity.pods="58";unmapped.responseObject.status.nodeInfo.bootID="0d0dd4f2-8829-4b03-9f29-794f4908281b";unmapped.responseObject.status.allocatable.cpu="3920m";actor.session.expiration_time=;metadata.product.data_classification=;actor.user.groups.0.domain=;resources.0.name="ip-192-001-02-03.ec2.internal";activity_id=1;unmapped.requestObject.status.conditions.0.lastHeartbeatTime="2021-09-07T20:37:28Z";unmapped.responseObject.status.conditions.2.lastTransitionTime="2021-09-07T20:37:28Z";unmapped.responseObject.status.addresses.0.type="InternalIP";actor.user.uid="heptio-authenticator-aws:123456789012:ABCD1234567890EXAMPLE";api.response.code=201;src_endpoint.mac=;unmapped.requestObject.status.conditions.2.lastTransitionTime="2021-09-07T20:37:28Z";unmapped.requestObject.status.capacity.attachable-volumes-aws-ebs="25";unmapped.requestObject.status.capacity.hugepages-2Mi="0";actor.user.groups.1.domain=;metadata.product.lang=;unmapped.responseObject.metadata.managedFields.0.operation="Update";unmapped.responseObject.status.capacity.hugepages-1Gi="0";src_endpoint.domain=;actor.session.expiration_time_dt=;unmapped.requestObject.status.nodeInfo.kubeletVersion="v1.21.2-eks-55daa9d";end_time=;unmapped.requestObject.status.conditions.2.status="False";time_dt="Not Yet Implemented timestamp::Timestamp";cloud.account.type_=;src_endpoint.namespace_pid=;src_endpoint.uid=;actor.user.type_id=0;src_endpoint.name=;unmapped.requestObject.status.conditions.1.type="DiskPressure";actor.session.is_remote=;unmapped.requestObject.status.conditions.2.lastHeartbeatTime="2021-09-07T20:37:28Z";unmapped.responseObject.spec.providerID="aws:///us-east-1f/i-12345678901";start_time=1631047050502680;unmapped.responseObject.metadata.resourceVersion="67933403";unmapped.responseObject.status.addresses.2.type="Hostname";unmapped.responseObject.status.conditions.3.reason="KubeletNotReady";unmapped.responseObject.status.conditions.3.type="Ready";unmapped.requestObject.status.conditions.1.reason="KubeletHasNoDiskPressure";http_request.user_agent="kubelet/v1.21.2 (linux/amd64) kubernetes/729bdfc";unmapped.responseObject.status.addresses.4.type="ExternalDNS";unmapped.kind="Event";unmapped.responseObject.status.addresses.1.address="12.000.22.33";metadata.product.uid=;unmapped.requestObject.status.capacity.hugepages-1Gi="0";unmapped.responseObject.status.conditions.1.message="kubelet has no disk pressure";http_request.url.port=;actor.session.uuid=;http_request.url.resource_type=;unmapped.responseObject.status.conditions.0.lastTransitionTime="2021-09-07T20:37:28Z";unmapped.requestObject.status.conditions.0.type="MemoryPressure";count=;unmapped.requestObject.apiVersion="v1";unmapped.responseObject.status.nodeInfo.machineID="ec2483c633b0e271f36ce14e45a361b8";unmapped.requestObject.status.conditions.1.message="kubelet has no disk pressure";observables.1.value="12.000.22.33";unmapped.requestObject.metadata.labels.beta.kubernetes.io/arch="amd64";metadata.profiles.1="datetime";metadata.modified_time=;start_time_dt="Not Yet Implemented timestamp::Timestamp";api.response.message=;metadata.product.name="Amazon EKS";unmapped.requestObject.status.conditions.3.reason="KubeletNotReady";unmapped.responseObject.metadata.labels.beta.kubernetes.io/instance-type="m5.xlarge";unmapped.requestObject.kind="Node";unmapped.responseObject.status.capacity.attachable-volumes-aws-ebs="25";metadata.profiles.0="cloud";observables.2.value="/api/v1/nodes";unmapped.requestObject.status.nodeInfo.kernelVersion="5.4.141-67.229.amzn2.x86_64";unmapped.responseObject.status.conditions.1.reason="KubeletHasNoDiskPressure";unmapped.requestObject.status.allocatable.hugepages-2Mi="0";unmapped.responseObject.metadata.labels.eks.amazonaws.com/nodegroup-image="ami-0193ebf9573ebc9f7";unmapped.responseObject.metadata.labels.alpha.eksctl.io/nodegroup-name="ng-5fe434eb";unmapped.responseObject.metadata.labels.kubernetes.io/hostname="ip-192-001-02-03.ec2.internal";http_request.args=;actor.user.uid_alt=;unmapped.requestObject.status.conditions.0.message="kubelet has sufficient memory available";cloud.region=;src_endpoint.hostname=;unmapped.requestObject.status.conditions.2.message="kubelet has sufficient PID available";api.response.error=;unmapped.responseObject.status.capacity.hugepages-2Mi="0";unmapped.responseObject.status.conditions.0.reason="KubeletHasSufficientMemory";unmapped.responseObject.status.nodeInfo.containerRuntimeVersion="docker://19.3.13";unmapped.responseObject.status.conditions.3.message="[container runtime status check may not have completed yet, container runtime network not ready: NetworkReady=false reason:NetworkPluginNotReady message:docker: network plugin is not ready: cni config uninitialized, CSINode is not yet initialized, missing node capacity for resources: ephemeral-storage]";unmapped.responseObject.status.nodeInfo.kernelVersion="5.4.141-67.229.amzn2.x86_64";actor.user.groups.2.type_=;unmapped.requestObject.metadata.labels.eks.amazonaws.com/nodegroup-image="ami-0193ebf9573ebc9f7";resources.0.cloud_partition=;http_request.url.hostname=;metadata.uid=;unmapped.requestObject.status.conditions.3.lastTransitionTime="2021-09-07T20:37:28Z";unmapped.responseObject.status.allocatable.hugepages-1Gi="0";category_name="Application Activity";actor.user.org=;unmapped.requestObject.status.conditions.0.reason="KubeletHasSufficientMemory";src_endpoint.instance_uid=;unmapped.responseObject.metadata.labels.eks.amazonaws.com/sourceLaunchTemplateVersion="1";observables.2.reputation=;actor.session.is_vpn=;metadata.logged_time_dt=;actor.process=;actor.user.groups.0.uid=;cloud.account.uid="arn:aws:sts::123456789012:assumed-role/example-test-161366663-NodeInstanceRole-abc12345678912/i-12345678901";http_request.url.subdomain=;observables.0.type_="User Name";unmapped.requestObject.status.addresses.2.type="Hostname";unmapped.responseObject.metadata.labels.beta.kubernetes.io/os="linux";unmapped.responseObject.status.addresses.1.type="ExternalIP";unmapped.requestObject.status.conditions.0.status="False";actor.user.groups.1.type_=;unmapped.requestObject.status.allocatable.attachable-volumes-aws-ebs="25";category_uid=6;severity_id=1;http_request.uid=;api.request.uid="f47c68f2-d3ac-4f96-b2f4-5d497bf79b64";unmapped.responseObject.spec.taints.0.key="node.kubernetes.io/not-ready";unmapped.responseObject.status.conditions.1.lastHeartbeatTime="2021-09-07T20:37:28Z";http_request.url.scheme=;metadata.product.feature.uid=;src_endpoint.vpc_uid=;src_endpoint.interface_name=;resources.0.namespace=;unmapped.requestObject.metadata.labels.eks.amazonaws.com/sourceLaunchTemplateId="lt-0f20d6f901007611e";unmapped.requestObject.metadata.name="ip-192-001-02-03.ec2.internal";metadata.log_provider=;dst_endpoint=;actor.user.full_name=;metadata.modified_time_dt=;unmapped.requestObject.metadata.labels.kubernetes.io/os="linux";actor.user.groups.2.domain=;unmapped.requestObject.status.nodeInfo.operatingSystem="linux";src_endpoint.zone=;unmapped.requestObject.status.conditions.3.lastHeartbeatTime="2021-09-07T20:37:28Z";unmapped.responseObject.status.allocatable.attachable-volumes-aws-ebs="25";http_request.referrer=;observables.2.type_id=6;cloud.zone=;cloud.project_uid=;resources.0.type_="nodes";unmapped.requestObject.status.allocatable.pods="58";actor.user.groups.2.desc=;metadata.product.vendor_name="AWS";unmapped.requestObject.status.nodeInfo.machineID="ec2483c633b0e271f36ce14e45a361b8";unmapped.requestObject.status.capacity.pods="58";unmapped.requestObject.status.addresses.0.type="InternalIP";unmapped.responseObject.metadata.annotations.volumes.kubernetes.io/controller-managed-attach-detach="true";unmapped.responseObject.metadata.labels.alpha.eksctl.io/cluster-name="ABCD1234567890EXAMPLE";unmapped.responseObject.metadata.labels.kubernetes.io/os="linux";unmapped.responseObject.status.addresses.0.address="192.000.22.33";unmapped.requestObject.metadata.labels.failure-domain.beta.kubernetes.io/region="us-east-1";unmapped.responseObject.status.addresses.2.address="ip-192-001-02-03.ec2.internal";unmapped.responseObject.metadata.creationTimestamp="2021-09-07T20:37:30Z";unmapped.requestObject.status.conditions.0.lastTransitionTime="2021-09-07T20:37:28Z";)] "#;
    is_ilf_parsable(str);
}

#[test]
fn ilf_with_bool() {
    let str = r#"ZeekFiles[*,*,1649964738.649337,(a=True;v=TrUe;r=False;f=false;)] "#;
    is_ilf_parsable(str);
    compare_ilf(
        str,
        "ZeekFiles",
        "*",
        "*",
        "1649964738.649337",
        vec![],
        vec![("a", "True"), ("v", "True"), ("r", "False"), ("f", "False")],
    );
}

#[test]
fn test_new_ilf() {
    let log = Log::new_with_timestamp(
        "ZeekFiles".to_string(),
        "*".to_string(),
        "*".to_string(),
        vec![],
        HashMap::new(),
    );
    println!("{:?}", log)
}

#[test]
// Allows the long list without line breaks
#[rustfmt::skip] 
fn test_all_files() {
    let mut failures: Vec<(String, String)> = vec![];
    let mut count = 0;
    let mut paths: Vec<_> = fs::read_dir("./tests/test_ilf")
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    paths.sort_by_key(|d| d.path());
    let files_that_should_fail = ["hblString3.ilf","hblString4RT.ilf","hblString4RTErr.ilf","hblString4RTStream.ilf","logAttrComma.ilf","logAttrComma2.ilf","logString4.ilf","logString4FreeVariable.ilf","logString4StringOps.ilf","logString5.ilf","logStringIrregularSpace.ilf","testBackSlash.ilf","testByte.ilf","testDictSize.ilf","testErrorILF.ilf","testEventSetAttrExp.ilf","testGroupAttrExEval.ilf","testGroupMultiAttrExEval0.ilf","testGroupMultiAttrExEval1.ilf","testGroupMultiAttrExEval2.ilf","testGroupMultiAttrExEval3.ilf","testGroupMultiAttrExEval4.ilf","testGroupMultiAttrExEval5.ilf","testGroupMultiAttrExEval6.ilf","testHB.ilf","testHexValues.ilf","testLoadErr.ilf","testLoadErr2.ilf","testLoadStream.ilf","testMixedHBPos.ilf","testMultiVarExpRT.ilf","testPNVC.ilf","testPrintEmptyComplexTypes.ilf","testRegexOR.ilf","testRegexParallel.ilf","testSensorTemp.ilf","testSingletonsGroup.ilf","testSingletonsNegMSet.ilf","testSingletonsNegMType.ilf","testSingletonsPosMSet.ilf","testSingletonsPosMSet2-1.ilf","testSingletonsVExpPos.ilf","testStringOps.ilf","testVarExpressionEval.ilf","testVariableExpressions.ilf","testZNegAndQuant.ilf","testZQuantifier.ilf", "logStringIrregularSpaceTimeStream.ilf", "testAlertSuppression.ilf", "testLiteralOnLeft.ilf", "testRunTimeExceptionLog.ilf", "testSetPrintBug.ilf", "testShortCircuit3.ilf", "sysMonLongLog.ilf", "testILFError.ilf"];
    
    for path in paths {
        count += 1;
        let contents = fs::read_to_string(path.path()).expect("should read file");
        let pathbuf = path.path();
        let filename = pathbuf
            .file_name()
            .expect("file has name")
            .to_str()
            .expect("file name valid unicode");
        let res = parse_logs(contents.as_str());
        match res {
            Ok((leftovers, _logs)) => {
                if !leftovers.trim().is_empty() {
                    failures.push((filename.to_string(), format!("Leftovers not parsed: {}", leftovers.trim())))
                }
                if files_that_should_fail.contains(&filename) {
                    failures.push((filename.to_string(), "Should not have parsed.".to_string()))
                }
            }
            Err(i) => {
                if !files_that_should_fail.contains(&filename) {
                    failures.push((filename.to_string(), i.parse_error.to_string()))
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} files out of {} failed to parse. Files:\n{}\n\nTraces:{}",
        failures.len(),
        count,
        failures
            .iter()
            .fold(String::new(), |c, (k, _)| c + k + "\n"),
        failures
            .iter()
            .fold(String::new(), |c, (k, v)| c + k + "\n\t" + v + "\n")
    )
}

fn is_ilf_parsable(ilf_str: &str) {
    let res = parse_log_to_tuple(ilf_str);
    println!("{:?}", res);
    assert!(res.is_ok())
}

/// helper function to make comparing ILF to an expected Log object cleaner. handles all the .into() conversions nicely.
fn compare_ilf(
    ilf_str: &str,
    log_type: &str,
    src: &str,
    dest: &str,
    timestamp: &str,
    fields: Vec<&str>,
    attributes: Vec<(&str, &str)>,
) {
    // Build the expected log object
    let expected_log = Log {
        log_type: log_type.to_string(),
        src: src.to_string(),
        dest: dest.to_string(),
        timestamp: timestamp.to_string(),
        fields: fields.into_iter().map(|s| s.to_string()).collect(),
        attributes: attributes
            .into_iter()
            .map(|(s1, s2)| {
                let mut attr_val: String = s2.to_string();
                attr_val.push(';');
                (
                    s1.to_string(),
                    match attr_val.try_into() {
                        Ok(v) => v,
                        Err(e) => panic!("{}", e),
                    },
                )
            })
            .collect(),
    };

    let res = parse_log_to_tuple(ilf_str);

    match res {
        Ok((leftover, log)) => {
            println!("Asserting that there are no ILF leftovers to parse");
            assert_eq!(leftover, "");
            println!("Asserting that the parsed ILF == expected output");
            assert_eq!(log, expected_log);
            println!("{:?}", log);
        }
        Err(e) => {
            println!("{:?}", e);
            panic!("ILF Failed to parse. {}", e.parse_error)
        }
    }
}
