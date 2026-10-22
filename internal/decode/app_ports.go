package decode

// ---------------------------------------------------------------- dispatchers

var httpPorts = map[uint16]bool{80: true, 81: true, 591: true, 3000: true, 3128: true, 8000: true, 8008: true, 8080: true, 8081: true, 8888: true}
var tlsPorts = map[uint16]bool{443: true, 465: true, 636: true, 853: true, 993: true, 995: true, 8443: true, 9443: true, 10443: true}
var dnsPorts = map[uint16]bool{53: true, 5353: true, 5355: true}
