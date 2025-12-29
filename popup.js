chrome.tabs.onActivated.addListener( function(activeInfo){
    chrome.tabs.get(activeInfo.tabId, function(tab){
        y = tab.url;
		$("#search").html("<td>Search</td><td>"+y+"</td>");
        console.log("you are here: "+y);
    });
});

chrome.storage.sync.QUOTA_BYTES = 5242880;
chrome.tabs.onUpdated.addListener((tabId, change, tab) => {
    if (tab.active && change.url) {
		$("#search").html("<td>Search</td><td>"+change.url+"</td>");
        console.log("you are here: "+change.url);           
    }
});
function storage_set(key,data,expired=1200) {
	data.expired = Date.now()+expired*1000;
	var string = JSON.stringify(data);
	//console.log("SAVE:"+key);
	chrome.storage.sync.set({[key]: string});
	return true;
}
function isJsonString(str) {
    try {
        JSON.parse(str);
    } catch (e) {
        return false;
    }
    return true;
}
function isIPv6(value)
{
  // See https://blogs.msdn.microsoft.com/oldnewthing/20060522-08/?p=31113 and
  // https://4sysops.com/archives/ipv6-tutorial-part-4-ipv6-address-syntax/
  const components = value.split(":");
  if (components.length < 2 || components.length > 8)
    return false;
  if (components[0] !== "" || components[1] !== "")
  {
    // Address does not begin with a zero compression ("::")
    if (!components[0].match(/^[\da-f]{1,4}/i))
    {
      // Component must contain 1-4 hex characters
      return false;
    }
  }

  let numberOfZeroCompressions = 0;
  for (let i = 1; i < components.length; ++i)
  {
    if (components[i] === "")
    {
      // We're inside a zero compression ("::")
      ++numberOfZeroCompressions;
      if (numberOfZeroCompressions > 1)
      {
        // Zero compression can only occur once in an address
        return false;
      }
      continue;
    }
    if (!components[i].match(/^[\da-f]{1,4}/i))
    {
      // Component must contain 1-4 hex characters
      return false;
    }
  }
  return true;
}
function validateIP(ip) {
    var is_valid = false;
    ip = ip.replace(/\s+/, "");

    if(ip.indexOf('/')!=-1){
        return false
    }
    
    try {
        var ipb = ip.split('.');
        if (ipb.length == 4) {
            for (var i = 0; i < ipb.length; i++) {
                var b = parseInt(ipb[i]);    
                if (b >= 0 && b <= 255) {
                    is_valid = true;
                } else {
                    is_valid = false;
                    break;
                }
            }
        }
    } catch (exception) {
        return false;
    }
    if (!is_valid) {
        return false;
    }
    return true;
}
function bytesToSize(bytes) {
   var sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
   if (bytes == 0) return '0 Byte';
   var i = parseInt(Math.floor(Math.log(bytes) / Math.log(1024)));
   return Math.round(bytes / Math.pow(1024, i), 2) + ' ' + sizes[i];
}
var type = "domain";
var site = "ip2whois.ru";
function check_domain(check_loc, check_list, counter = 0) {
	$("#ping_results").append("<tr class='loader'><td colspan='3'><div class='uk-text-center'><div uk-spinner></div></div></td></tr>");
	$.get("https://ip2whois.ru/api/traceroute/ping/"+check_loc+"/"+check_list[counter],function(data){
		$(".loader").remove();
		if(data.success) {
			$("#ping_results").append("<tr><td><img src='"+data.loc_img+"' title='"+data.loc_dc+"' width='16'/> "+data.name+":</td><td>"+data.rtt_statistics.avg.value+" ms<br>"+data.rtt_summary.packets_transmitted+" / "+data.rtt_summary.packets_received+"</td><td>"+data.icmp_sequences[0].target_ip+"</td></tr>");
		} else {
			$("#ping_results").append("<tr><td><img src='"+data.loc_img+"' title='"+data.loc_dc+"' width='16'/> "+data.name+":</td><td colspan='2'>"+data.message+"</td></tr>");
		}
		if(counter != check_list.length-1) check_domain(check_loc, check_list, counter+1);
	});
}
function check_domain2(check_loc, protocol, check_list, counter = 0) {
	$("#http_results").append("<tr class='loader'><td colspan='3'><div class='uk-text-center'><div uk-spinner></div></div></td></tr>");
	$.post("https://ip2whois.ru/api/traceroute/get/"+check_loc+"/"+check_list[counter],{proto:protocol},function(data){
		$(".loader").remove();
		if(data.success) {
			if(data.http_code == 0) data.http_code = data.http_code + " Failed";
			if(data.http_code == 200) data.http_code = data.http_code + " OK";
			if(data.http_code == 301) data.http_code = data.http_code + " Moved Permanently";
			if(data.http_code == 302) data.http_code = data.http_code + " Found";
			if(data.http_code == 304) data.http_code = data.http_code + " Not Modified";
			if(data.http_code == 307) data.http_code = data.http_code + " Temporary Redirect";
			if(data.http_code == 308) data.http_code = data.http_code + " Permanent Redirect";
			if(data.http_code == 400) data.http_code = data.http_code + " Bad Request";
			if(data.http_code == 401) data.http_code = data.http_code + " Unauthorized";
			if(data.http_code == 403) data.http_code = data.http_code + " Forbidden";
			if(data.http_code == 404) data.http_code = data.http_code + " Not Found";
			if(data.http_code == 500) data.http_code = data.http_code + " Internal Server Error";
			if(data.http_code == 502) data.http_code = data.http_code + " Bad Gateway";
			if(data.http_code == 503) data.http_code = data.http_code + " Service Unavailable";
			if(data.http_code == 504) data.http_code = data.http_code + " Gateway Timeout";
			$("#http_results").append("<tr><td><img src='"+data.loc_img+"' title='"+data.loc_dc+"' width='16'/> "+data.name+":</td><td>"+data.http_code+"</td><td>"+data.primary_ip+"</td></tr>");
		} else {
			$("#http_results").append("<tr><td><img src='"+data.loc_img+"' title='"+data.loc_dc+"' width='16'/> "+data.name+":</td><td colspan='2'>"+data.message+"</td></tr>");
		}
		if(counter != check_list.length-1) check_domain2(check_loc, protocol, check_list, counter+1);
	});
}


function ping_new(host,path,callback) {
	var start = new Date();
		$.ajax({
			url: host+"/"+path+"?q="+start.getTime(),
			data: {},
			crossDomain: true,
			timeout: 3000,
			success: function(){
				var end = new Date();
				callback((end.getTime() - start.getTime()-2), host);
			},
			error: function(xhr, statusText, err){
				var end = new Date();
				callback((end.getTime() - start.getTime())+" "+err, host);
			}
		});
			
}
function ping_callback(data,id) {
	$("#latency_ping").html(data +" ms");
	ping_diff = ping_diff+data;
	if(data > 100) {
		$("#latency_ping").css("color","#a61818");
	} else if(data > 70 && data <=100) {
		$("#latency_ping").css("color","#ff0000");
	} else if(data <=70 && data > 40) {
		$("#latency_ping").css("color","#d7ac34");
	} else {
		$("#latency_ping").css("color","#44a618");
	}
	ping_in_progress=false;
}

const delay = ms => new Promise(res => setTimeout(res, ms));
var speedtext,ping_diff=0,speed_started=false,ping_in_progress=false,last_sp=0,start_speedtest,total_percent=0;
const count_try = 4;
function updateProgress(rec,fsize=1) {
	if(rec !=0) {
		var percent = ((rec/fsize)*100).toFixed(1);
		if(percent % 20 == 0.0) {
			last_sp = performance.now();
			var speed_current = ((rec*8)/(1024*1024*((last_sp - start_speedtest)/1000))).toFixed(0);
			$('#progress_speed_text').html(speed_current+' Mbps');
		}
		$('#progress_speed').attr("stroke-dashoffset",(261 - (261*(total_percent+percent/count_try)/100).toFixed(0))+'px');
	} else {
		total_percent = 0;
	}
}

async function downloadWithProgress(url, expectedSize) {
  const startTime = start_speedtest = performance.now();

  const response = await fetch(url + "&cachedrop=" + Math.random());
  const reader = response.body.getReader();
  let received = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) {
		total_percent = total_percent + 100/count_try;
		break;
	}

    received += value.length;
    if (expectedSize) {
      updateProgress(received, expectedSize);
    }
  }

  const endTime = performance.now();
  const duration = (endTime - startTime) / 1000;
  return { duration, bytes: received };
}

async function autoSelectSize() {
  //speedtext.innerText = "Calibrating…";
  updateProgress(0);

  const testUrl = speedtest_url + "testfile512k.bin?size=small";
  const result = await downloadWithProgress(testUrl);

  const speedMbps = (result.bytes * 8) / (1024 * 1024 * (result.duration-(ping_diff/1000)));
  if (speedMbps < 20) return 1 * 1024 * 1024;
  if (speedMbps < 45) return 2 * 1024 * 1024; 
  if (speedMbps < 100) return 5 * 1024 * 1024; 
  if (speedMbps < 200) return 10 * 1024 * 1024; 
  if (speedMbps < 400) return 25 * 1024 * 1024; 
  return 50 * 1024 * 1024;
}
async function runSpeedTest() {
	if(!speed_started) {
		speed_started = true;
  speedtext.innerText = "Preparing…";
  $("#speedtestbutton").html("Processing..");
  $("#speedtestbutton").addClass("disabled");
$('#dl_speed').html('<svg width="200" height="200" viewBox="-12.875 -12.875 128.75 128.75" version="1.1" xmlns="http://www.w3.org/2000/svg" style="transform:rotate(-90deg)">'
    +'<circle r="41.5" cx="51.5" cy="51.5" fill="transparent" stroke="#ffffff" stroke-width="2"></circle>'
    +'<circle id="progress_speed" r="41.5" cx="51.5" cy="51.5" stroke="#007bff" stroke-width="6" stroke-linecap="round" stroke-dashoffset="261px" fill="transparent" stroke-dasharray="260.62px"></circle>'
    +'<text x="20px" y="54px" fill="#000000" font-size="12px" font-weight="bold" style="transform:rotate(90deg) translate(0px, -99px)" id="progress_speed_text">Preparing</text>'
  +'</svg>');
  updateProgress(0);
  $("#latency_ping_text").html("RTT to Cloudflare*");
  for (let i = 0; i < count_try; i++) {
	ping_new("https://"+site,"testbandwidth/latency.ttf",ping_callback);
	ping_in_progress=true;
	 while(ping_in_progress) {
		await delay(500);
	 }
  }
  ping_diff = (ping_diff/count_try).toFixed(2);
$("#latency_ping").html("Avg "+ ping_diff +" ms");
if(ping_diff > 100) {
	$("#latency_ping").css("color","#a61818");
} else if(ping_diff > 70 && ping_diff <=100) {
	$("#latency_ping").css("color","#ff0000");
} else if(ping_diff <=70 && ping_diff > 40) {
	$("#latency_ping").css("color","#d7ac34");
} else {
	$("#latency_ping").css("color","#44a618");
}

  var targetSize = await autoSelectSize();
  targetSize = await autoSelectSize(); //temporary fix?
	const filetest = targetSize/(1024*1024);
  //speedtext.innerText = `Testing speed (${(targetSize / 1024 / 1024).toFixed(1)} MB)…`;
  updateProgress(0);
  var tobytes=0,speed_t=0,dur_t=0,mbps;
  const url = speedtest_url + `testfile`+filetest+`m.bin?size=${targetSize}`;
  for (let i = 0; i < count_try; i++) {
	
	 current_rep = i;
  const result = await downloadWithProgress(url, targetSize);
	dur_t = dur_t + result.duration;
	tobytes = tobytes + result.bytes;
	mbps = (result.bytes * 8) / (1024 * 1024 * result.duration);
	$('#progress_speed_text').html(mbps.toFixed(0)+' Mbps');
	//$('#progress_speed').attr("stroke-dashoffset",(261 - ((261*i)/count_try).toFixed(0))+'px');
  }
  mbps = (tobytes * 8) / (1024 * 1024 * dur_t);
	const sizedlmb = tobytes/(1024*1024);
  speedtext.innerText =
    `Speed: ${mbps.toFixed(2)} Mbps\nSize: ${sizedlmb.toFixed(2)} MiBytes`;
  $("#speedtestbutton").html("Start");
  $("#speedtestbutton").removeClass("disabled");
  ping_diff=0;
	speed_started = false;
	total_percent = 0;
	} else {
		alert('Test already started! Wait for complete it.');
	}
}

async function ping_test_rtt() {
	  $("#latency_ping_text").html("Ping CF");
  for (let i = 0; i < count_try; i++) {
	ping_new("https://"+site,"testbandwidth/latency.ttf",ping_callback);
	ping_in_progress=true;
	 while(ping_in_progress) {
		await delay(500);
	 }
  }
  ping_diff = (ping_diff/count_try).toFixed(2);
$("#latency_ping").html("Avg "+ ping_diff +" ms");
if(ping_diff > 100) {
	$("#latency_ping").css("color","#a61818");
} else if(ping_diff > 70 && ping_diff <=100) {
	$("#latency_ping").css("color","#ff0000");
} else if(ping_diff <=70 && ping_diff > 40) {
	$("#latency_ping").css("color","#d7ac34");
} else {
	$("#latency_ping").css("color","#44a618");
}
}

function getClientInfo() {
  const info = {
    userAgent: navigator.userAgent,
    platform: navigator.platform,
    language: navigator.language,
    languages: navigator.languages,

    screen: {
      width: window.screen.width,
      height: window.screen.height,
      availWidth: window.screen.availWidth,
      availHeight: window.screen.availHeight,
      colorDepth: window.screen.colorDepth,
      pixelRatio: window.devicePixelRatio
    },

    connection: navigator.connection ? {
      effectiveType: navigator.connection.effectiveType,
      downlink: navigator.connection.downlink,
      rtt: navigator.connection.rtt,
      saveData: navigator.connection.saveData
    } : null,

    gpu: getAccurateGPU()
  };
 const userAgent = navigator.userAgent;
  if (userAgent.indexOf("Chrome") > -1 && userAgent.indexOf("Edge") === -1) {
    info.browserName = "Chrome";
  } else if (userAgent.indexOf("Firefox") > -1) {
    info.browserName = "Firefox";
  } else if (userAgent.indexOf("Safari") > -1 && userAgent.indexOf("Chrome") === -1) {
    info.browserName = "Safari";
  } else if (userAgent.indexOf("Edge") > -1) {
    info.browserName = "Edge";
  } else if (userAgent.indexOf("MSIE") > -1 || userAgent.indexOf("Trident") > -1) {
    info.browserName = "Internet Explorer";
  } else {
    info.browserName = "Unknown";
  }
  return info;
}
function getAccurateGPU() {
  const canvas = document.createElement("canvas");
  const gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
  if (!gl) return null;

  const ext = gl.getExtension("WEBGL_debug_renderer_info");

  let vendor = ext
    ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL)
    : gl.getParameter(gl.VENDOR);

  let renderer = ext
    ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)
    : gl.getParameter(gl.RENDERER);

  return {
    vendor: normalizeVendor(vendor),
    model: cleanGPU(renderer),
    rawVendor: vendor,
    rawModel: renderer
  };
}

function cleanGPU(str) {
  if (!str) return null;
  str = str.trim();
  const adrenoMatch = str.match(/adreno[\s\-_]*(\(tm\))?\s*\d+/i);
  if (adrenoMatch) {
    return adrenoMatch[0]
      .replace(/\(tm\)/i, "TM")
      .replace(/\s+/g, " ")
      .trim();
  }
  const angleMatch = str.match(/,\s*([^()]+?)\s*(\(|$)/);
  if (angleMatch) return angleMatch[1].trim();
  const generic = str.match(/[A-Za-z0-9()_\- ]+/);
  if (generic) return generic[0].trim();

  return str;
}
function normalizeVendor(vendorStr) {
  if (!vendorStr) return null;
  vendorStr = vendorStr.trim();

  const match = vendorStr.match(/\(([^)]+)\)/);
  if (match) {
    return match[1].trim(); 
  }

  if (/google\s+inc/i.test(vendorStr)) {
    return null; 
  }

  if (/nvidia/i.test(vendorStr)) return "NVIDIA";
  if (/amd|ati/i.test(vendorStr)) return "AMD";
  if (/intel/i.test(vendorStr)) return "Intel";
  if (/qualcomm/i.test(vendorStr)) return "Qualcomm";
  if (/apple/i.test(vendorStr)) return "Apple";

  return vendorStr;
}
$('a[data-toggle="tab"]').on('click', function (e) {
  if(e.target.id == "hardware_list-tab") {
	  if($('.hardware_info').html() == "") {
		  chrome.system.cpu.getInfo(function(data) {
			$('.hardware_info').append("<tr><td>Processor:</td><td>"+data.modelName+" x "+data.numOfProcessors+"</td></tr>");
			
			var arg = getClientInfo();
			if(typeof arg.gpu !== "undefined") {
					$(".hardware_info").append("<tr><td>GPU:</td><td>"+arg.gpu.model+"</td></tr>");
					$(".hardware_info").append("<tr><td>GPU:</td><td><img src='https://cdn.ninja/ip2whois/img/icons/"+arg.gpu.vendor.toLowerCase()+".svg' title='"+arg.gpu.vendor+"' style='max-height:20px;max-width:80px;'> "+arg.gpu.vendor+"</td></tr>");
				}

				if(typeof arg.connection !== "undefined" && arg.connection != null) {
					if(typeof arg.connection.effectiveType !== "undefined") {
						if(arg.connection.effectiveType == "4g") {
							arg.connection.effectiveType = "4G/Wifi/Cable";
						}
						$(".hardware_info").append("<tr><td>Connection:</td><td>"+arg.connection.effectiveType+"</td></tr>");
					} else {
						$(".hardware_info").append("<tr><td>Connection:</td><td>Unsupported</td></tr>");
					}
					if(typeof arg.connection.effectiveType !== "undefined") {
						$(".hardware_info").append("<tr><td id='latency_ping_text'>Ping:</td><td id='latency_ping'>"+arg.connection.rtt+" ms</td></tr>");
					} else {
						$(".hardware_info").append("<tr><td>RTT:</td><td id='latency_ping'>Process.</td></tr>");
					}
				} else {
					$(".hardware_info").append("<tr><td>Connection:</td><td>Unsupported</td></tr>");
					$(".hardware_info").append("<tr><td>Ping:</td><td id='latency_ping'>Process.</td></tr>");
				}
				ping_test_rtt();
				speedtest_url = "https://"+site+"/testbandwidth/"; 
		  });
		  chrome.system.memory.getInfo(function(data) {
			$('.hardware_info').append("<tr><td>Memory:</td><td>total: "+bytesToSize(data.capacity)+"<br/> free: "+bytesToSize(data.availableCapacity)+"</td></tr>");
		  });
		  chrome.system.display.getInfo(function(data) {
			$('.hardware_info').append("<tr><td>Display:</td><td>"+data[0].bounds.width+" x "+data[0].bounds.height+"</td></tr>");
		  });
	  } else {
		  console.log("tab is not null");
	  }
  }
  else if(e.target.id == "ping_list-tab") {
	  $.ajaxSetup({
		   headers:{'Accept': "application/json"}
		});
		if($("#ping_results").html() == "") {
			var host = $("#ping_list-tab").attr("host-name");
			$.get("https://ip2whois.ru/api/testpoints",function(data){
				if(data.success) {
					check_domain(host, data.points, 0);
				}
			});
		}
  }
  else if(e.target.id == "http-tab") {
	  $.ajaxSetup({
		   headers:{'Accept': "application/json"}
		});
		if($("#http_results").html() == "") {
			var host = $("#ping_list-tab").attr("host-name");
			var proto = $("#ping_list-tab").attr("host-proto");
			$.get("https://ip2whois.ru/api/testpoints",function(data){
				if(data.success) {
					check_domain2(host, proto, data.points, 0);
				}
			});
		}
  }
})
chrome.tabs.query({
    active: true,
    lastFocusedWindow: true
}, function(tabs) {
	chrome.storage.sync.get("ip2whois-updated", function(data2) {
		val = data2["ip2whois-updated"];
		if(isJsonString(val)) {
			var cache = JSON.parse(val);
			if(cache.version != manifest.version) {
				$("#update_list-tab").show();
				$("#update").html("New version is availible v "+cache.version+": <a href='"+cache.href+"' target='_blank'><button type='button' class='uk-button uk-button-primary'>Download</button></a>");
				//console.log(cache);
			}
		}
	});
    var tab = tabs[0];
	var proto = tab.url.split(":");
	var manifest = chrome.runtime.getManifest();
	$("#version").html(manifest.version);
	const curdate = new Date();
	$("#year_holder").html(curdate.getFullYear());
	if(proto[0] == "http" || proto[0] == "https") {
		var url = proto[1].split("/");
		url[0] = url[0].replace(":","");
		$("#ping_list-tab").attr("host-name",url[2]);
		$("#ping_list-tab").attr("host-proto",proto[0]);
		$(this).show();
		$("#search").html("<div class='uk-text-center'><div uk-spinner></div></div>");
		if(/^((?!-))(xn--)?[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]{0,1}\.(xn--)?([a-z0-9\-]{1,61}|[a-z0-9-]{1,30}\.[a-z]{2,})$/.test(url[2])) {
			try {
				var c_key = url[2].replace(".","_");
				c_key = "ip2whois-"+c_key;
				var val;
				chrome.storage.sync.get(c_key, function(data2) {
						var ip2 = url[2].split(":");
						if(validateIP(ip2[0]) || isIPv6(ip2[0])) {
							type = "ip";
							url[2] = ip2[0];
						} else {
							type = "domain";
						}
					val = data2[c_key];
					if(isJsonString(val)) {
						//console.log("GET:"+c_key);
						var data = JSON.parse(val);
						if(data.expired < Date.now()) {
							chrome.storage.sync.remove([c_key]);
						}
						if(type == "ip") {
							$("#search").html("<a href='https://ip2whois.ru/ip/"+url[2]+"' target='_blank'>"+url[2]+"</a>");
						} else {
							$("#search").html("<a href='https://ip2whois.ru/domain/"+url[2]+"' target='_blank'>"+url[2]+"</a>");
						}
							if(data.success) {
								storage_set(c_key,data);
								if(type == "domain") {
									if(typeof data.domain_utf8 !== "undefined" && data.domain_utf8 != url[2]) {
										$("#search").html("<a href='https://ip2whois.ru/domain/"+url[2]+"' target='_blank'>"+data.domain_utf8+"</a>");
									}
								}
								if(typeof data.IPv4 !== "undefined") {
									if(typeof data.IP_list !== "undefined" && data.IP_list.length > 1) {
										$.each(data.IP_list, function(_, v){
											if(v.type == 4) {
												if($("#IPv4").html() == "") $("#IPv4").append(v.value);
												else $("#IPv4").append("<br>" + v.value);
											}
										});
										if($("#IPv4").html() == "") {
											$("#IPv4").html(data.IPv4);
										}
									} else {
										$("#IPv4").html(data.IPv4);
									}
									if(type == "ip") {
										$(".IPv6").hide();
									}
								}
								else $("#IPv4").html("no info");
								if(typeof data.IPv6 !== "undefined") {
									if(typeof data.IP_list !== "undefined" && data.IP_list.length > 1) {
										$.each(data.IP_list, function(_, v){
											if(v.type == 6) {
												if($("#IPv6").html() == "") $("#IPv6").append(v.value);
												else $("#IPv6").append("<br>" + v.value);
											}
										});
										if($("#IPv6").html() == "") {
											$("#IPv6").html(data.IPv6);
										}
									} else {
										if(data.IPv6 == "::") {
											$(".IPv6").hide();
										} else $("#IPv6").html(data.IPv6);
									}
									if(type == "ip") {
										$(".IPv4").hide();
									}
								}
								else $("#IPv6").html("no info");
								if(type == "ip") {
									$(".dns").hide();
								} else {
									$.each(data.dns, function(_, v){
										$("#dns").append(v.name + " (" + v.ip + ")<br/>");
									});
								}
								if(typeof data.rank !== "undefined" && data.rank != "") $("#rank").html(data.rank);
								else $(".rank").hide();
								$("#owner").html("<a href='https://ip2whois.ru/asn/"+data.ASN+"' target='_blank'>"+data.ISP+"</a>");
								if(typeof data.ASNimg !== "undefined" && data.ASNimg != "") $("#owner").append(" <img src='"+data.ASNimg+"' style='max-height:32px;max-width:150px'/>");
								$("#ptr").html(data.PTR);
								if(typeof data.ISP_City !== "undefined" && data.rank != "") $("#location").html("<img src='"+data.img+"' width='16' /> " + data.Country + ", " + data.City);
								else $("#location").html("<img src='"+data.img+"' width='16' /> " + data.Country);
							} else {
								$("#IPv4").html("no connection");
								$("#IPv6").html("no connection");
								$("#owner").html("no connection");
								$("#location").html("no connection");
							}
					} else {
						$.get("https://ip2whois.ru/api/whoisinfo/"+type+"/"+url[2], function(data) {
							//console.log(data);
							if(type == "ip") {
								$("#search").html("<a href='https://ip2whois.ru/ip/"+url[2]+"' target='_blank'>"+url[2]+"</a>");
							} else {
								$("#search").html("<a href='https://ip2whois.ru/domain/"+url[2]+"' target='_blank'>"+url[2]+"</a>");
							}
							if(data.success) {
								storage_set(c_key,data);
								if(typeof data.IPv4 !== "undefined") {
									if(typeof data.IP_list !== "undefined" && data.IP_list.length > 1) {
										$.each(data.IP_list, function(_, v){
											if(v.type == 4) {
												if($("#IPv4").html() == "") $("#IPv4").append(v.value);
												else $("#IPv4").append("<br>" + v.value);
											}
										});
										if($("#IPv4").html() == "") {
											$("#IPv4").html(data.IPv4);
										}
									} else {
										$("#IPv4").html(data.IPv4);
									}
									if(type == "ip") {
										$(".IPv6").hide();
									}
								}
								else $("#IPv4").html("no info");
								if(typeof data.IPv6 !== "undefined") {
									if(typeof data.IP_list !== "undefined" && data.IP_list.length > 1) {
										$.each(data.IP_list, function(_, v){
											if(v.type == 6) {
												if($("#IPv6").html() == "") $("#IPv6").append(v.value);
												else $("#IPv6").append("<br>" + v.value);
											}
										});
										if($("#IPv6").html() == "") {
											$("#IPv6").html(data.IPv6);
										}
									} else {
										if(data.IPv6 == "::") {
											$(".IPv6").hide();
										} else $("#IPv6").html(data.IPv6);
									}
									if(type == "ip") {
										$(".IPv4").hide();
									}
								}
								else $("#IPv6").html("no info");
								if(type == "ip") {
									$(".dns").hide();
								} else {
									$.each(data.dns, function(_, v){
										$("#dns").append(v.name + " (" + v.ip + ")<br/>");
									});
								}
								if(typeof data.rank !== "undefined" && data.rank != "") $("#rank").html(data.rank);
								else $(".rank").hide();
								$("#owner").html("<a href='https://ip2whois.ru/asn/"+data.ASN+"' target='_blank'>"+data.ISP+"</a>");
								if(typeof data.ASNimg !== "undefined" && data.ASNimg != "") $("#owner").append(" <img src='"+data.ASNimg+"' style='max-height:32px;max-width:150px'/>");
								$("#ptr").html(data.PTR);
								$("#location").html("<img src='"+data.img+"' width='16' /> " + data.Country);
							} else {
								$("#IPv4").html("no connection");
								$("#IPv6").html("no connection");
								$("#owner").html("no connection");
								$("#location").html("no connection");
							}
						});		
					}
				});
						
			}
			catch (e) {
				$("#IPv4").html("no connection");
				$("#IPv6").html("no connection");
				$("#owner").html("no connection");
				$("#location").html("no connection");
				console.log("Error: "+e);
			}
		} else {
			console.log("invalid domain name");
				$("#search").html("<a href='https://ip2whois.ru/domain/"+url[2]+"' target='_blank'>"+url[2]+"</a>");
				$("#IPv4").html("invalid domain name");
				$("#IPv6").html("invalid domain name");
				$("#owner").html("invalid domain name");
				$("#location").html("invalid domain name");
		}
	} else {
		if(proto[0] == "chrome") {
			try {
				$.get("https://ip2whois.ru/api/whoisinfo/ip/my", function(data) {
					//console.log(data);
					if(data.success) {
						
						if(typeof data.IPv4 !== "undefined") {
							$("#IPv4").html(data.IPv4);
							$("#search").html("<a href='https://ip2whois.ru/ip/"+data.IPv4+"' target='_blank'>"+data.IPv4+"</a>");
							$(".IPv6").hide();
						}
						else $("#IPv4").html("no info");
						if(typeof data.IPv6 !== "undefined") {
							$("#IPv6").html(data.IPv6);
							$("#search").html("<a href='https://ip2whois.ru/ip/"+data.IPv6+"' target='_blank'>"+data.IPv6+"</a>");
							$(".IPv4").hide();
						}
						else $("#IPv6").html("no info");
						$(".dns").hide();
						$("#owner").html("<a href='https://ip2whois.ru/asn/"+data.ASN+"' target='_blank'>"+data.ISP+"</a>");
						if(typeof data.ASNimg !== "undefined" && data.ASNimg != "") $("#owner").append(" <img src='"+data.ASNimg+"' height='32' style='max-width:150px'/>");
						$("#ptr").html(data.PTR);
						$("#location").html("<img src='"+data.img+"' width='16' /> " + data.Country);
					} else {
						$("#IPv4").html("no connection");
						$("#IPv6").html("no connection");
						$("#owner").html("no connection");
						$("#location").html("no connection");
					}
				});				
			}
			catch (e) {
				$("#IPv4").html("no connection");
				$("#IPv6").html("no connection");
				$("#owner").html("no connection");
				$("#location").html("no connection");
				console.log("Error: "+e);
			}
		}
	}
});
