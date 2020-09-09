pub const DEBOT_ABI: &'static str = r#"{
	"ABI version": 2,
	"header": ["time", "expire"],
	"functions": [
		{
			"name": "fetch",
			"inputs": [
			],
			"outputs": [
				{"components":[{"name":"desc","type":"bytes"},{"components":[{"name":"desc","type":"bytes"},{"name":"name","type":"bytes"},{"name":"actionType","type":"uint8"},{"name":"attrs","type":"bytes"},{"name":"to","type":"uint8"},{"name":"id","type":"uint8"},{"name":"misc","type":"cell"}],"name":"actions","type":"tuple[]"},{"name":"id","type":"uint8"}],"name":"contexts","type":"tuple[]"}
			]
		},
		{
			"name": "start",
			"inputs": [
			],
			"outputs": [
			]
		},
		{
			"name": "quit",
			"inputs": [
			],
			"outputs": [
			]
		},
		{
			"name": "getVersion",
			"inputs": [
			],
			"outputs": [
				{"name":"name","type":"bytes"},
				{"name":"semver","type":"uint24"}
			]
		},
		{
			"name": "exec",
			"inputs": [
				{"name":"state","type":"uint8"},
				{"name":"action","type":"uint8"},
				{"name":"flags","type":"uint256"},
				{"name":"argc","type":"uint8"},
				{"name":"argv","type":"uint256[]"}
			],
			"outputs": [
				{"name":"value0","type":"uint256"}
			]
		},
		{
			"name": "getDebotOptions",
			"inputs": [
			],
			"outputs": [
				{"name":"options","type":"uint8"},
				{"name":"debotAbi","type":"bytes"},
				{"name":"targetAbi","type":"bytes"},
				{"name":"targetAddr","type":"address"}
			]
		},
		{
			"name": "setArgc",
			"inputs": [
				{"name":"count","type":"uint8"}
			],
			"outputs": [
			]
		},
		{
			"name": "setArgv",
			"inputs": [
				{"name":"params","type":"uint256[]"}
			],
			"outputs": [
			]
		},
		{
			"name": "constructor",
			"inputs": [
			],
			"outputs": [
			]
		}
	],
	"data": [
	],
	"events": [
	]
}
"#;