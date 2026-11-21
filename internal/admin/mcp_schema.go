package admin

import "encoding/json"

func objectSchema(definition string) json.RawMessage {
	base := `{"type":"object","additionalProperties":false`
	if definition != "" {
		base += "," + definition
	}
	return json.RawMessage(base + "}")
}

const dashboardSchema = `"properties":{
	"range":{"type":"string","enum":["15m","1h","24h"],"default":"24h"}
}`

const historySchema = `"properties":{
	"client":{"type":"string","description":"One or more comma-separated IPs or anonymized client IDs."},
	"question":{"type":"string","description":"Case-insensitive substring of the DNS name."},
	"outcome":{"type":"string","description":"Outcome such as blocked, allowed, cache hit, local dns, or NXDOMAIN."},
	"type":{"type":"string","description":"DNS question type, such as A, AAAA, or TYPE65."},
	"after":{"type":"string","format":"date-time","description":"Inclusive RFC 3339 lower time bound."},
	"until":{"type":"string","format":"date-time","description":"Exclusive RFC 3339 upper time bound."},
	"before":{"type":"integer","minimum":0,"description":"Use the next cursor from a previous response."},
	"limit":{"type":"integer","minimum":1,"maximum":200,"default":50}
}`

const previewSchema = `"required":["client","question"],"properties":{
	"client":{"type":"string","description":"IPv4 or IPv6 address whose policy to evaluate."},
	"question":{"type":"string","description":"DNS name or HTTP(S) URL."},
	"type":{"type":"string","default":"A","description":"DNS type such as A, AAAA, PTR, or HTTPS."}
}`

const devicesSchema = `"properties":{
	"id":{"type":"string","description":"Look up an exact device ID."},
	"search":{"type":"string","description":"Substring of a name, device ID, MAC, address, network or group."},
	"controller":{"type":"string","description":"Exact controller ID."},
	"site":{"type":"string","description":"Exact site ID."},
	"presence":{"type":"string","enum":["connected","absent","manual","legacy"]},
	"after":{"type":"string","description":"Use the next cursor from a previous response."},
	"limit":{"type":"integer","minimum":1,"maximum":200,"default":50}
}`

const policyPatchSchema = `"required":["revision"],"properties":{
	"revision":{"type":"integer","minimum":1,"description":"Current revision returned by get_policies."},
	"default":{"$ref":"#/$defs/policy","description":"Replace the default policy."},
	"groups":{"type":"object","description":"Replace listed groups by key. A null value removes a group.",
		"additionalProperties":{"anyOf":[{"$ref":"#/$defs/policy"},{"type":"null"}]}},
	"assignments":{"type":"array","description":"Replace the full CIDR assignment list. Use [] to clear.",
		"items":{"type":"object","additionalProperties":false,"required":["prefix"],"properties":{
			"prefix":{"type":"string"},"device":{"type":"string"},"group":{"type":"string"},"policy":{"$ref":"#/$defs/policy"}
		}}},
	"services":{"type":"object","description":"Replace custom service definitions by key. A null value removes an override.",
		"additionalProperties":{"anyOf":[{"$ref":"#/$defs/service"},{"type":"null"}]}}
},"$defs":{
	"policy":{"type":"object","additionalProperties":false,"properties":{
		"mode":{"type":"string","enum":["","filtered","unfiltered","local-only","deny-all"]},
		"pool":{"type":"string"},
		"rules":{"type":"array","items":{"$ref":"#/$defs/rule"}},
		"services":{"type":"array","items":{"type":"string"},"description":"Omit to inherit. Use [] to clear."},
		"subscriptions":{"type":"array","items":{"type":"string"},"description":"Omit to inherit. Use [] to clear."}
	}},
	"rule":{"type":"object","additionalProperties":false,"required":["name"],"properties":{
		"id":{"type":"string"},"name":{"type":"string"},"suffix":{"type":"boolean"},"allow":{"type":"boolean"}
	}},
	"service":{"type":"object","additionalProperties":false,"required":["version"],"properties":{
		"version":{"type":"string"},
		"domains":{"type":"array","items":{"$ref":"#/$defs/rule"}},
		"rules":{"type":"array","items":{"type":"string"}}
	}}
}`
