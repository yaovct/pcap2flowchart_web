<?php
// Created: 2020/02/11
// by Victor Yang
// To convert a pcap file to a call trace flow (png format) with a web mouseover interation.
// INPUT: a pcap filename
// OUTPUT: a call trace flow figure and a web page
//phpinfo();

$version = '20200211a';

ini_set('memory_limit', '256M');
date_default_timezone_set("Asia/Taipei");
require_once __DIR__.'/common.php';

###################### Global variables ######################
$q850_json_file = 'q850_code.json';
$device_json_file = 'device_list.json';
$input_filename = '';
$output_filename = '';
$filter_string = '-Y "sip||rtp||dns||diameter||isup"';
$server_count = 0;

//Start Time
$app_start = getmicrotime();

$q850_arr = array();
if(file_exists($q850_json_file)) {
	$str = file_get_contents($q850_json_file);
	$result = json_decode($str, true); // decode the JSON into an associative array
	for($i=0; $i<count($result); $i++) {
		$q850_arr[$result[$i]['code']] = $result[$i]['definition'];
	}
}

$probe_arr = array();
if(file_exists($device_json_file)) {
	$str = file_get_contents($device_json_file);
	$result = json_decode($str, true); // decode the JSON into an associative array
	for($i=0; $i<count($result); $i++) {
		$probe_data['sitename'] = $result[$i]['sitename'];
		$probe_data['devicename'] = $result[$i]['devicename'];
		$probe_data['alias'] = $result[$i]['alias'];
		$probe_arr[$result[$i]['ip_addr']] = $probe_data; // assign ip_addr as the key
	}
}

if(!empty($_POST['pcapfilename'])) {
	$input_filename = $_POST['pcapfilename'];
} else {
	print "You need to give a pcap filename!\n";
	exit;
}

if(!empty($_POST['filterstring'])) {
	$filter_string = "-Y ".$_POST['filterstring'];
}

$decode_as     = "-d udp.port==5072,sip";
$fields_string = "-Tfields -e frame.time -e ip.src -e ip.dst -e sip.from.user -e sip.to.user -e sip.Request-Line -e sip.Method ".
                 "-e sip.Status-Line -e sip.CSeq.seq -e sip.CSeq.method -e sip.Expires -e sip.contact.uri ".
                 "-e sip.Content-Type -e sip.Call-ID -e sip.User-Agent -e sip.P-Charging-Vector -e sip.P-Asserted-Identity ".
                 "-e sip.P-Served-User -e sdp.connection_info.address ".
                 "-e sdp.media.media -e sdp.media.port -e sdp.media.format -e sip.Reason -e isup.cause_indicator ".
                 "-e rtp.p_type -e rtp.seq -e rtp.marker -e rtp.timestamp -e rtp.ssrc ".
                 "-e rtpevent.event_id -e rtpevent.end_of_event ".
                 "-e dns.flags.response -e dns.flags.rcode -e dns.naptr.service -e dns.naptr.regex ".
	               "-e dns.count.answers -e dns.resp.name ".
	               "-e diameter.Session-Id -e diameter.cmd.code -e diameter.flags.request -e diameter.applicationId ".
				         "-e diameter.User-Name -e diameter.Public-Identity -e diameter.Result-Code -e diameter.Experimental-Result-Code ".
				         "-e mtp3.opc -e mtp3.dpc -e mtp3.sls ".
				         "-e isup.cic -e isup.message_type -e isup.calling -e isup.called ".
				         "-e isup.redirecting -e isup.cause_indicator";

$tshark_cmd = "tshark $filter_string $decode_as $fields_string -r $input_filename -t ad";
$tshark_rst = shell_exec($tshark_cmd); // Execute an extermal program via shell and return the complete output
//$tshark_cmd;

###################### Step 1: Proceed the tshark output content ######################
$arr = preg_split('/\n/',$tshark_rst);
$ln = 0; # count for each trace line
$g = 0; # for sip_group
$sip_group = array(); # for different sip call id
$a = array(); # temporary array
$trace = array(); # to record each trace
foreach ($arr as $line) {
	if(!strlen($line)) continue;

	$values = preg_split('/\t/',$line);
	# Apr 27, 2018 12:59:48.529061000
	$t_ = preg_split('/\./',$values[0]);

	###################
	# process time
	###################
	$t = strtotime($t_[0]); # Apr 27, 2018 12:59:48 => 1524805188
	$date_ = strftime("%Y-%m-%d",$t);
	$time_ = strftime("%H:%M:%S",$t);
	$usec_ = substr($values[0],21,7);
	$trace[$ln]['datetime'] = $t;
	$trace[$ln]['millisecond'] = $usec_;
	$trace[$ln]['time'] = $time_.$usec_;
	$tshark_time[$ln] = $values[0];
	
	# set output filename
	if(!$ln) {
		$output_filename = strftime('%Y%m%d%H%M%S',$t).$usec_;
	}

	###################
	# process the probe name with ip.addr
	###################
	# to check total servers
	if(isset($probe_arr[$values[1]])) {
		if($probe_arr[$values[1]]['alias']) {
			$a = &$servers[$probe_arr[$values[1]]['alias']];
			if(!$a) {
				$server_count += 1;
				$a['order'] = $server_count;
				$a['sitename'] = $probe_arr[$values[1]]['sitename'];
				$a['node_ip'] = $values[1];
			} else {
				if(strpos($a['node_ip'], '\n')) {
					$nn = explode("\\n",$a['node_ip']);
					$chk = 0;
					foreach ($nn as $n) {
						if($n == $values[1]) {
							$chk = 1;
							break;
						}
					}
					if(!$chk) {
						$a['node_ip'] .= '\n'.$values[1];
					}
				} else if($a['node_ip'] != $values[1]) {
					$a['node_ip'] .= '\n'.$values[1];
				}
			}
		} else {
			$a = &$servers[$probe_arr[$values[1]]['devicename']];
			if(!$a) {
				$server_count += 1;
				$a['order'] = $server_count;
				$a['sitename'] = $probe_arr[$values[1]]['sitename'];
				$a['node_ip'] = $values[1];
			}
		}
	} elseif(preg_match('/^[0-9]{4}$/', $values[1])){ # PointCode: 4 digits
		$a = &$servers[$values[1]];
		if(!$a) {
			$server_count += 1;
			$a['order'] = $server_count;
			$a['devicename'] = "OPC";
			$a['sitename'] = getSS7_SiteName($values[1]);
		}
	} else {
		$a = &$servers[$values[1]];
		if(!$a) {
			$server_count += 1;
			$a['order'] = $server_count;
			$a['sitename'] = "";
		}
	}
	if(isset($probe_arr[$values[2]])) {
		if($probe_arr[$values[2]]['alias']) {
			$a = &$servers[$probe_arr[$values[2]]['alias']];
			if(!$a) {
				$server_count += 1;
				$a['order'] = $server_count;
				$a['sitename'] = $probe_arr[$values[2]]['sitename'];
				$a['node_ip'] = $values[2];
			} else {
				if(strpos($a['node_ip'], '\n')) {
					$nn = explode("\\n",$a['node_ip']);
					$chk = 0;
					foreach ($nn as $n) {
						if($n == $values[2]) {
							$chk = 1;
							break;
						}
					}
					if(!$chk) {
						$a['node_ip'] .= '\n'.$values[2];
					}
				} else if($a['node_ip'] != $values[2]) {
					$a['node_ip'] .= '\n'.$values[2];
				}
			}
		} else {
			$a = &$servers[$probe_arr[$values[2]]['devicename']];
			if(!$a) {
				$server_count += 1;
				$a['order'] = $server_count;
				$a['sitename'] = $probe_arr[$values[2]]['sitename'];
				$a['node_ip'] = $values[2];
			}
		}
	} elseif(preg_match('/^[0-9]{4}$/', $values[2])){ # PointCode: 4 digits
		$a = &$servers[$values[2]];
		if(!$a) {
			$server_count += 1;
			$a['order'] = $server_count;
			$a['devicename'] = "DPC";
			$a['sitename'] = getSS7_SiteName($values[2]);
		}
	} else {
		$a = &$servers[$values[2]];
		if(!$a) {
			$server_count += 1;
			$a['order'] = $server_count;
			$a['sitename'] = "";
		}
	}
	###################
	# process ip.addr
	###################
	if(strpos($values[1],'.')) { # ip
		$trace[$ln]['type'] = 'sip';
		$trace[$ln]['saddr'] = $values[1];
		$trace[$ln]['daddr'] = $values[2];
		###################
		# process from.user
		###################
//		if(strpos($values[3], ',')) {
//			$s_from_user = preg_split('/,/',$values[3]); # sip.from.user
////			$ur = 0;
////			for($ur; $ur<count($s_from_user); $ur++) {
////				if($s_from_user[$ur] == $caller) {
////					$values[3] = $s_from_user[$ur];
////					break;
////				}
////			} // $ur is what we need
//			// get value from the valid $ur
//			for($k=4; $k<substr_count($fields_string, '-e '); $k++) {
//				$b = preg_split('/,/',$values[$k]);
//				if(array_key_exists($ur, $b)) {
//					$values[$k] = $b[$ur];
//				} else {
//					$values[$k] = "";
//				}
//			}
//		}
		$trace[$ln]['from'] = $values[3]; # sip.from.user
		$trace[$ln]['to'] = $values[4]; # sip.to.user
		$trace[$ln]['request-line'] = $values[5]; # sip.Request-Line
		$trace[$ln]['method'] = "";
		if($values[6]) {
			$trace[$ln]['method'] .= $values[6]; # sip.Method
		}
		if($values[7]) {
			$trace[$ln]['status-line'] = $values[7]; # sip.Status-Line
			$values[7] = preg_replace('/SIP\/2.0 /','',$values[7]);
			if(strpos($values[7], ' - ')) {
				$s_ = preg_split('/ - /',$values[7]);
				$trace[$ln]['method'] .= "$s_[0]_{{$s_[1]}}";
			} else {
				$trace[$ln]['method'] .= $values[7];
			}
		}
		$trace[$ln]['cseq'] = $values[8]; # sip.CSeq.seq
		$trace[$ln]['cmethod'] = $values[9]; # sip.CSeq.method
		$trace[$ln]['expires'] = $values[10]; # sip.Expires
		$trace[$ln]['curi'] = $values[11]; # sip.contact.uri
		$trace[$ln]['ctype'] = $values[12]; # sip.Content-Type
		$trace[$ln]['callid'] = $values[13]; # sip.Call-ID
    //判斷sip_call_id
    if(!$g) {
    	$sip_group[$g++] = $values[13];
    } elseif(!in_array($values[13], $sip_group)) {
    	$sip_group[$g++] = $values[13];
    }
		$trace[$ln]['usagent'] = $values[14]; # sip.User-Agent
		$trace[$ln]['pchargingv'] = html_entity_decode($values[15], ENT_QUOTES); # sip.P-Charging-Vector
		$trace[$ln]['passertedi'] = html_entity_decode($values[16], ENT_QUOTES); # sip.P-Asserted-Identity
		$trace[$ln]['pservedusr'] = html_entity_decode($values[17], ENT_QUOTES); # sip.P-Served-User
		$trace[$ln]['con_info_addr'] = $values[18]; # sdp.connection_info.address
		$trace[$ln]['mtype'] =  $values[19]; # sdp.media.media
		$trace[$ln]['mport'] =  $values[20]; # sdp.media.port
		$trace[$ln]['mformat'] =  $values[21]; # sdp.media.media
		$trace[$ln]['reason'] =  html_entity_decode(htmlspecialchars_decode($values[22])); # sip.Reason
		$trace[$ln]['causei'] =  $values[23]; # isup.cause_indicator (BYE)
		# rtp
		if(is_numeric($values[24])) { # rtp.p_type
			$trace[$ln]['type'] = 'rtp';
			$trace[$ln]['callid'] = $trace[$ln]['rtp_type'] = $values[24]; # rtp.p_type
			$trace[$ln]['method'] = getShortPayloadType($trace[$ln]['rtp_type']);
	    //判斷sip_call_id
	    if(!in_array($values[24], $sip_group)) {
	    	$sip_group[$g++] = $values[24];
	    }
			$trace[$ln]['rtp_seq'] = $values[25]; # rtp.seq
			$trace[$ln]['rtp_marker'] = $values[26]; # rtp.marker
			$trace[$ln]['rtp_timestamp'] = $values[27]; # rtp.timestamp
			$trace[$ln]['rtp_ssrc'] = $values[28]; # rtp.ssrc
			if(is_numeric($values[29])) {
				$trace[$ln]['dtmf_num'] = $values[29]; # rtpevent.event_id
				$trace[$ln]['dtmf_end'] = $values[30]; # rtpevent.end_of_event
				$trace[$ln]['method'] .= $values[29].($values[30] ? " (E)" : "");
			}
			if($trace[$ln]['rtp_marker']) {
				$trace[$ln]['method'] .= ' (M)';
			}
		}
		# dns
		if(is_numeric($values[31])) {
			###################
			# process from.user
			###################
			# dns.flags.response
			$trace[$ln]['type'] = 'dns';
			if(!$values[31]) {
				$trace[$ln]['method'] = "Query";
			} else {
				$trace[$ln]['method'] = "Response";
			}
			$trace[$ln]['enum_number'] = $trace[$ln]['from'] = $trace[$ln]['to'] = $caller;
			if(!empty($answer_num)) {
				$trace[$ln]['enum_number'] = $trace[$ln]['to'] = $answer_num;
			}
			$trace[$ln]['callid'] = $trace[$ln]['transaction_id'] = $transaction_id; # diameter.Session-Id
			//transaction_id
			if(!in_array($transaction_id, $sip_group)) {
	    	$sip_group[$g++] = $transaction_id;
		  }
			$trace[$ln]['query_name'] = $query_name;
			$trace[$ln]['reply_code'] = $values[32]; # dns.flags.rcode
			$trace[$ln]['naptr_service'] = $values[33]; # dns.naptr.service
			$trace[$ln]['naptr_regex'] = $values[34]; # dns.naptr.regex
			if($values[35] > 0) { # dns.count.answers
				$v = preg_split('/,/',$values[36]);
				$trace[$ln]['answer_name'] = html_entity_decode($v[0]); # dns.resp.name
			} else {
				$trace[$ln]['answer_name'] = "";
			}
		}
		# diameter
		if(!empty($values[37])) {

			$trace[$ln]['type'] = 'dia';

			if(strpos($values[37], ',')!==false) { # diameter.Session-Id
				$s_session_id = preg_split('/,/',$values[37]); # diameter.Session-Id
				for($ur=0; $ur<count($s_session_id); $ur++) {
					if(strpos($session_id, $s_session_id[$ur])!==false) {
						$values[37] = $s_session_id[$ur];
						break;
					}
				} // $ur is what we need
				// get value from the valid $ur
				for($k=38; $k<substr_count($fields_packet, '-e '); $k++) {
					$b = preg_split('/,/',$values[$k]);
					if(array_key_exists($ur, $b)) {
						$values[$k] = $b[$ur];
					} else {
						$values[$k] = "";
					}
				}
			}
			$trace[$ln]['callid'] = $trace[$ln]['session_id'] = $values[37]; # diameter.Session-Id
			//session_id
			if(!in_array($values[37], $sip_group)) {
	    	$sip_group[$g++] = $values[37];
		  }
			$trace[$ln]['cmd_code'] = $values[38];
			$trace[$ln]['method'] = getShortCommandCode($values[38],$values[39]); # diameter.cmd.code, diameter.flags.request
			$trace[$ln]['cmd_code_detail'] = getAllCommandCode($values[38],$values[39]); # diameter.cmd.code, diameter.flags.request
			$trace[$ln]['request'] = $values[39];
			$trace[$ln]['application_id'] = $values[40]; # diameter.applicationId
			$trace[$ln]['user_name'] = $values[41]; # diameter.User-Name
			$trace[$ln]['public_id'] = $values[42]; # diameter.Public-Identity
			$trace[$ln]['result_code'] = $values[43]; # diameter.Result-Code
			$trace[$ln]['ex_result_code'] = $values[44]; # diameter.Experimental-Result-Code
		}
		# m2ua
		if(!empty($values[45])) {

			$trace[$ln]['type'] = 'm2u';

			$trace[$ln]['opc'] = $values[45]; # mtp3.opc
			$trace[$ln]['dpc'] = $values[46]; # mtp3.dpc
			$trace[$ln]['sls'] = $values[47]; # mtp3.sls
			# for showing server info
			$trace[$ln]['from'] = $caller; # sip.from.user
			$trace[$ln]['to'] = $callee; # sip.to.user
			###################
			# process ISUP
			###################
			$trace[$ln]['callid'] = $trace[$ln]['cic'] = $values[48]; # isup.cic
			//isup_cic
			if(!in_array($values[48], $sip_group)) {
	    	$sip_group[$g++] = $values[48];
		  }
			$trace[$ln]['msg_type'] = $values[49]; # isup.message_type
			$trace[$ln]['message_type'] = getISUPMessageType($values[49]);
			$trace[$ln]['method'] = getISUPMessageTypeAbbrev($values[49]); # isup.message_type

			$trace[$ln]['calling'] = $values[50]; # isup.calling
			$trace[$ln]['called'] = $values[51]; # isup.called
			$trace[$ln]['redir'] = $values[52]; # isup.redirecting
			$trace[$ln]['cause_i'] = $values[53]; # isup.cause_indicator
		}
	}
	$ln++;
} // end of ...foreach(line)
#krumo($trace);
###################### Step 4: produce gnu script ######################
$mypic = $output_filename.'.png';
$mygnu = $output_filename.'.gnu';
$mzpic = $output_filename.'_t.png';
$mzgnu = $output_filename.'_t.gnu';
$tmpgnu = "plot1.txt";

if(file_exists($mygnu)) {
	unlink($mypic);
  unlink($mygnu); // 移除已有的gnu檔案
}
if(file_exists($mzgnu)) {
  unlink($mzpic);
  unlink($mzgnu); // 移除已有的gnu檔案
}

$pic_width = '1024';
$flows = $ln;
$pic_height = ($flows+10)*20;

$area_blank = Array();

###################
# produce gnu file
###################
$f[0] = $fp = fopen($mygnu, "w");
$f[1] = $tp = fopen($mzgnu, "w");

$fp0 = fopen($tmpgnu, "w");
fputs($fp0, "0 0\n");
fclose($fp0);

$cutline = ';'.chr(13).chr(10);

$font_style = ' font "Arial,12"';
if($server_count > 5 && $server_count < 11)
	$font_style = ' font "Arial,'.(17 - $server_count).'"';
elseif($server_count >= 11)
	$font_style = ' font "Arial,7"';

#fputs($fp, 'set fontpath "/usr/share/fonts/zh_TW/TrueType/"'.$cutline);
fputs($fp, 'set xrange [0:'.($server_count+1).']'.$cutline);
fputs($fp, 'set yrange [0:'.($flows*2+2).']'.$cutline); // 將Y軸間距增為兩倍 放arrow & label
fputs($tp, 'set xrange [0:'.($server_count+1).']'.$cutline);
fputs($tp, 'set yrange [0:'.($flows*2+2).']'.$cutline); // 將Y軸間距增為兩倍 放arrow & label

for($i=0; $i<count($f); $i++) {
  # 讓坐標軸沒有刻度 - $fp
  fputs($f[$i], 'set border 0'.$cutline);
  fputs($f[$i], 'unset xtics'.$cutline);
  fputs($f[$i], 'unset ytics'.$cutline);
  fputs($f[$i], 'set lmargin 0'.$cutline);
  fputs($f[$i], 'set rmargin 0'.$cutline);
  fputs($f[$i], 'set tmargin 7'.$cutline); # top margin determine the top text
 	fputs($f[$i], 'set title "Total Flows: '.$flows.' ( ' .$date_.' )" font "large" '.$cutline);
 	fputs($f[$i], 'set title offset 0,2'.$cutline);
}
$duration = $trace[$ln-1]['datetime'] + $trace[$ln-1]['millisecond'] - $trace[0]['datetime'] - $trace[0]['millisecond'];
//			$callid = $trace[0]['callid'];
//			if($server_count < 6)
//				$callid = preg_replace('/\@/','\\\\\@',$callid);
fputs($fp, 'set xlabel "(Duration: {/:Bold '.number_format($duration,3).'} sec)'.
           '\nhttp://nbr.cht.com.tw" tc rgb "black"'.$cutline);
fputs($fp, 'set label "'.get_current_user().'\\\@'.getHostByName(getHostName()).
           '\nat '.date("Y-m-d H:i:s").'" at '.($server_count+0.8).', -1 right tc rgb "slategray"'.$cutline);

###################
# title: show server name with ip and phone number
###################
$t_ServerName = "";
foreach ($servers as $x => $v) {
	$o = $v['order'];
	$s = $v['sitename'];
	$n = isset($v['node_ip']) ? $v['node_ip'] : "";
	# 清空area_blank
	if ($o<=$server_count) {
		$area_blank[$o] = 1; # 從時間開始的area，都是blank
	}

	# 建立設備Y軸
	fputs($fp, 'set arrow from '.$o.',0 to '. $o.','.($flows*2+2).' nohead lw 2 lc rgb "black" back'.$cutline);
	fputs($tp, 'set arrow from '.$o.',0 to '. $o.','.($flows*2+2).' nohead lw 2 lc rgb "black" back'.$cutline);

	# 建立設備名稱
	$t_srv = "";
	$x = preg_replace('/\_/','\\\\\_',$x);
	if($n) {
		$t_srv = $s.'\n{/Times:Bold '.$x.'}\n'.$n;
	} else {
		$t_srv = $s.'\n'.$x;
	}
	if($o == $server_count) {
		$t_ServerName .= '"'.$t_srv.'" '.$o;
	} else {
		$t_ServerName .= '"'.$t_srv.'" '.$o.', ';
	}
}
fputs($fp, 'set style arrow 1 head empty size screen 0.017,15 ls 10'.$cutline);
fputs($fp, 'set x2tics ('.$t_ServerName.')'.$font_style.' textcolor rgb "blue"'.$cutline);
fputs($tp, 'set x2tics ('.$t_ServerName.')'.$font_style.' textcolor rgb "blue"'.$cutline);

$startA = $endA = 0;
for($y=0; $y<$flows; $y++) {
	$group_fgcolor = "dark-violet";
	$group_bgcolor = "orange";
	for($z=0; $z<=count($sip_group); $z++) {
		if ($trace[$y]['callid'] == $sip_group[$z]) {
			switch($z%16) {
				case 0:
					$group_fgcolor = "dark-blue";
					$group_bgcolor = "light-green";
					break;
				case 2:
					$group_fgcolor = "brown";
					$group_bgcolor = "light-blue";
					break;
				case 3:
					$group_fgcolor = "dark-violet";
					$group_bgcolor = "orange";
					break;
				case 4:
					$group_fgcolor = "dark-green";
					$group_bgcolor = "violet";
					break;
				case 5:
					$group_fgcolor = "purple";
					$group_bgcolor = "light-grey";
					break;
				case 6:
					$group_fgcolor = "black";
					$group_bgcolor = "khaki";
					break;
				case 7:
					$group_fgcolor = "black";
					$group_bgcolor = "light-coral";
					break;
				case 8:
					$group_fgcolor = "black";
					$group_bgcolor = "green";
					break;
				case 9:
					$group_fgcolor = "black";
					$group_bgcolor = "gold";
					break;
				case 10:
					$group_fgcolor = "black";
					$group_bgcolor = "pink";
					break;
				case 11:
					$group_fgcolor = "black";
					$group_bgcolor = "skyblue";
					break;
				case 12:
					$group_fgcolor = "black";
					$group_bgcolor = "light-cyan";
					break;
				case 13:
					$group_fgcolor = "black";
					$group_bgcolor = "dark-yellow";
					break;
				case 14:
					$group_fgcolor = "black";
					$group_bgcolor = "light-salmon";
					break;
				case 15:
					$group_fgcolor = "black";
					$group_bgcolor = "plum";
					break;
				}
			break;
		} // end ... if ($trace[$y]['callid'] == $sip_group[$z]) {
	} // end ... for(z...)

	foreach ($servers as $x => $v) {
		if(isset($probe_arr[$trace[$y]['saddr']])) {
			if($probe_arr[$trace[$y]['saddr']]['alias'] == $x ||
			   $probe_arr[$trace[$y]['saddr']]['devicename'] == $x) {
				$startA = $v['order'];
			}
		} else {
			if($trace[$y]['saddr'] == $x) {
				$startA = $v['order'];
			}
		}
		if(isset($probe_arr[$trace[$y]['daddr']])) {
			if($probe_arr[$trace[$y]['daddr']]['alias'] == $x ||
			   $probe_arr[$trace[$y]['daddr']]['devicename'] == $x) {
				$endA = $v['order'];
			}
		} else {
			if($trace[$y]['daddr'] == $x) {
				$endA = $v['order'];
			}
		}
	}
	# clean blank
	if ($startA - $endA >= 1) {
		for ($x=0; $x < $startA-$endA; $x++) {
			$area_blank[$endA+$x] = 0;
		}
	} else if($endA - $startA >= 1) {
		for ($x=0; $x < $endA-$startA; $x++) {
			$area_blank[$startA+$x] = 0;
		}
	}
	# show arrow
	#
	# status
	#
	$color = "brown";
	if(!strcmp($trace[$y]['type'],'sip')) {
		if(preg_match('/^[456]/', $trace[$y]['method'])) {
			$color = "red";
		} else if(preg_match('/^[123]/', $trace[$y]['method'])) {
			$color = "dark-green";
		}
	} else if(!strcmp($trace[$y]['type'],'dns')) {
		if($trace[$y]['reply_code']=="") {
			$trace[$y]['method'] .= ' ('.$query_num.')';

		} elseif($trace[$y]['reply_code']==0) {
			$trace[$y]['method'] .= ' ('.$answer_num.')';
			$color = "dark-green";

		} else {
			$trace[$y]['method'] .= ' ('.getDNSReplyCode($trace[$y]['reply_code']).')';
			$color = "red";
		}
	} elseif(!strcmp($trace[$y]['type'],'dia')) {
		if($trace[$y]['request']) {
			$trace[$y]['method'] .= ' ('.getApplicationId($trace[$y]['application_id']).')';
			$color = "dark-green";

		} else {
			if($trace[$y]['result_code']) {
				$trace[$y]['method'] .= ' ('.preg_replace('/\_/','\\\\\_',getResultCode($trace[$y]['result_code'])).')';
			}
			$color = "red";
		}
	} elseif(!strcmp($trace[$y]['type'],'m2u')||!strcmp($trace[$y]['type'],'ss7')) {
		if($trace[$y]['cause_i']) {
			$trace[$y]['method'] .= ' ('.$trace[$y]['cause_i'].')';
			$color = "red";
			if($trace[$y]['cause_i'] == 16 || $trace[$y]['cause_i'] == 99) {
				$color = "dark-green";
			}
		}
	}

	// 指派area 的 座標
	$area_coord[$y] = ($pic_width/($server_count+1)*($startA)).','.
	                  (143+(($pic_height-183)*($y)/($flows+1))).','.
	                  ($pic_width/($server_count+1)*($endA)).','.
	                  (143+(($pic_height-183)*($y+1)/($flows+1)));

	$trace[$y]['method'] = ($y+1).": ".$trace[$y]['method'];

	if ($startA < $endA) {
		fputs($fp, 'set arrow from '.$startA.','.(($flows-$y-0.5)*2).' to '.$endA.','.(($flows-$y-0.5)*2).' lw 2 lc rgb "'.$group_fgcolor.'" back as 1'.$cutline);
		fputs($fp, 'set label "'.$trace[$y]['method'].'" at '.(($endA-$startA)/2+$startA).', '.(($flows-$y)*2).$font_style.' center tc rgb "'.$color.'"'.$cutline);
		# time label
		fputs($fp, 'set label "'.$trace[$y]['time'].'" at '.(0.5).', '.(($flows-$y)*2).$font_style.' center tc rgb "'.$color.'"'.$cutline);
	} else {
		fputs($fp, 'set arrow from '.$startA.','.(($flows-$y-0.5)*2).' to ' .$endA. ','.(($flows-$y-0.5)*2).' lw 2 lc rgb "'.$group_fgcolor.'" back as 1'.$cutline);
		fputs($fp, 'set label "'.$trace[$y]['method'].'" at '.(($endA-$startA)/2+$startA).', '.(($flows-$y)*2).$font_style.' center tc rgb "'.$color.'"'.$cutline);
		# time label
		fputs($fp, 'set label "'.$trace[$y]['time'].'" at '.($server_count+0.5).', '.(($flows-$y)*2).$font_style.' center tc rgb "'.$color.'"'.$cutline);
	}
	if(!strcmp($trace[$y]['type'],'sip')) {
		fputs($fp, 'set obj rect from 1,'.(($flows-$y-0.5)*2).' to ' .($server_count). ','.(($flows-$y)*2+1).' fc rgb "'.$group_bgcolor.'" fs noborder'.$cutline);
	} elseif(!strcmp($trace[$y]['type'],'dns')) {
		fputs($fp, 'set obj rect from 1,'.(($flows-$y-0.5)*2).' to ' .($server_count). ','.(($flows-$y)*2+1).' fc rgb "'.$group_bgcolor.'" fs pattern 5 noborder'.$cutline);
	} elseif(!strcmp($trace[$y]['type'],'dia')) {
		fputs($fp, 'set obj rect from 1,'.(($flows-$y-0.5)*2).' to ' .($server_count). ','.(($flows-$y)*2+1).' fc rgb "'.$group_bgcolor.'" fs pattern 2 noborder'.$cutline);
	} elseif(!strcmp($trace[$y]['type'],'m2u')||!strcmp($trace[$y]['type'],'ss7')) {
		fputs($fp, 'set obj rect from 1,'.(($flows-$y-0.5)*2).' to ' .($server_count). ','.(($flows-$y)*2+1).' fc rgb "'.$group_bgcolor.'" fs pattern 1 noborder'.$cutline);
	} elseif(!strcmp($trace[$y]['type'],'rtp')) {
		fputs($fp, 'set obj rect from 1,'.(($flows-$y-0.5)*2).' to ' .($server_count). ','.(($flows-$y)*2+1).' fc rgb "'.$group_bgcolor.'" fs pattern 10 noborder'.$cutline);
	}
} // end...for($y=0; $y<$flows; $y++)

# 清空無畫線之處
for ($i=0; $i<count($area_blank); $i++) {
	if(isset($area_blank[$i])&&$area_blank[$i])
		fputs($fp, 'set obj rect from '.($i).',1 to '.($i+1).','.($flows*2+1).' fc rgb "white" fs noborder'.$cutline);
}

fputs($fp, 'set term png'.$cutline);
fputs($fp, 'set term png size '.$pic_width.','.$pic_height.''.$cutline);
fputs($fp, 'set output "'.$mypic.'"'.$cutline);
fputs($fp, 'plot "'.$tmpgnu.'" using 1:2 notitle'.$cutline);
fputs($fp, 'set output'.$cutline);
fclose($fp);

fputs($tp, 'set term png'.$cutline);
fputs($tp, 'set term png size '.$pic_width.',95'.$cutline);
fputs($tp, 'set output "'.$mzpic.'"'.$cutline);
fputs($tp, 'plot "plot1.txt" using 1:2 notitle'.$cutline);
fputs($tp, 'set output'.$cutline);
fclose($tp);

###################### GNUPLOT 繪圖 ######################
if(file_exists($mygnu)) {
	system('gnuplot "'.$mygnu.'"',$result); // 呼叫gnuplot，記得將路徑設定於環境變數中
	unlink($mygnu);
	system('gnuplot "'.$mzgnu.'"',$result); // 呼叫gnuplot，記得將路徑設定於環境變數中
	unlink($mzgnu);

  $im = @ImageCreateFromPng($mypic);
  $zm = @ImageCreateFromPng($mzpic);

  /* See if it failed */
  if($im && $zm) {
    ImagePng($im, $mypic); // To file
    ImagePng($zm, $mzpic); // To file
    //sleep($flows/80);
    ImageDestroy($im);
    ImageDestroy($zm);
  }
}
unlink($tmpgnu);

?>
<!DOCTYPE html>
<html lang="zh-TW">
<head>
	<meta charset="utf-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<meta name="description" content="To convert a pcap file to a call trace flow (png format) with a web mouseover interation.">
	<meta name="author" content="yaovct">
	
	<title>Interaction of the call trace</title>

	<!-- Bootstrap -->
	<link href="css/bootstrap.min.css" rel="stylesheet">

	<style type="text/css">
		.wrapper {
		/*	position:relative; */
			min-height:90%
			height:auto !important;
			height:100%;
			margin:0 auto -70px; /* the bottom margin is the negative value of the footer's height */
		}
	  .popover-area {
	      display: block;
	      width: 150px;
	      height: 150px;
	      background: #9C7A43;
	      text-indent: -9999px;
	  }
    .popover {
        max-width: none;
    }
	</style>	
</head>
<body>
<div class="wrapper">
	<div id="pic_main">
		<img id="mypic" border="0" src="<?=$mypic?>" class="image-map" usemap="#mymap"/>
		<map name="mymap">
<?php
	for($i=0; $i<$flows; $i++) {
		print '<area href="#" coords="'.$area_coord[$i].'"'.
	         ' data-id='.$i.
	         ' data-packet_info="'.$tshark_time[$i].'">';
	} // end for(i...)
?>
		</map>
		<div id="pic_title" style="position: absolute; display: none">
			<img id="mzpic" border="0" src="<?=$mzpic?>" />
		</div>
	</div>
</div>
<script src="js/jquery-3.4.1.min.js"></script>
<script src="js/bootstrap-tooltip.js"></script>
<script src="js/bootstrap-popover.js"></script>
<script>

// 浮動視窗顯示的內容
var contents = [
<?php

$float_txt = '';

	for($i=0; $i<$flows; $i++) {
		if($i>0) {
			$float_txt .= ',';
		}
		$float_txt .= '\''.
		  '<div style="width: ';

		if(!strcmp($trace[$i]['type'],'sip')) {

			if(strlen($trace[$i]['request-line'])<=30 && strlen($trace[$i]['callid'])<=30 && strlen($trace[$i]['curi'])<=30) {
				$width = 250;
			} else if(strlen($trace[$i]['request-line'])<=55 && strlen($trace[$i]['callid'])<=35 && strlen($trace[$i]['curi'])<=30) {
				$width = 350;
			} else if(strlen($trace[$i]['request-line'])<=80 && strlen($trace[$i]['callid'])<=40 && strlen($trace[$i]['curi'])<=30) {
				$width = 450;
			} else {
				$width = 550;
			}
			$float_txt .=
				$width.
			  'px;"><i>Flow_No</i> : <b>'.($i+1).'</b><hr>'.
			  ($trace[$i]['request-line'] ? '<b><font color=darkred>'.$trace[$i]['request-line'].'</font></b>' : '').
			  (array_key_exists('status-line', $trace[$i]) ? '<font color=darkred>'.$trace[$i]['status-line'].'</font>' : '').
			  ($trace[$i]['callid'] ? '<p>Call-ID = <font color=blue>'.$trace[$i]['callid'].'</font>' : '').
			  ($trace[$i]['from'] ? '<br>SIP_From_Address = <font color=indigo>'.$trace[$i]['from'].'</font>' : '').
			  ($trace[$i]['to'] ? '<br>SIP_To_Address = <font color=blueviolet>'.$trace[$i]['to'].'</font>' : '').

			  ($trace[$i]['cmethod'] ? '<p>CSeq_Method = <font color=brown>'.$trace[$i]['cmethod'].'</font>' : '').
			  ($trace[$i]['cseq'] ? '<br>Sequence_Number = <font color=green>'.$trace[$i]['cseq'].'</font>' : '').
			  ($trace[$i]['expires'] ? ', Expires = <font color=blue>'.$trace[$i]['expires'].'</font>' : '').
			  (preg_match('/(\S+)[ ;]cause=(\d+)[ ;]text="(.*)"/', $trace[$i]['reason'], $rs) ? 
			  	'<br><b>Reason = </b>'.$rs[1].' <font color=darkpink>'. $rs[3].'</font> ('.$rs[2].')' : '').

			  ($trace[$i]['pchargingv'] ? '<p>P_Charging_Vector = <font color=green>'.$trace[$i]['pchargingv'].'</font>' : '').
			  ($trace[$i]['passertedi'] ? '<br>P_Asserted_Identity = <font color=purple>'.$trace[$i]['passertedi'].'</font>' : '').
			  ($trace[$i]['pservedusr'] ? '<br>P_Served_User = <font color=purple>'.$trace[$i]['pservedusr'].'</font>' : '').
			  ($trace[$i]['usagent'] ? '<br>User_Agent = <font color=red>'.$trace[$i]['usagent'].'</font>' : '').
			  ($trace[$i]['curi'] ? '<br>Contact_URI = <font color=blue>'.$trace[$i]['curi'].'</font>' : '').
			  ($trace[$i]['ctype'] ? '<br>Content_Type = <font color=green>'.$trace[$i]['ctype'].'</font>' : '').

			  ($trace[$i]['mtype'] ? '<p>Media_Type = <font color=brown>'.$trace[$i]['mtype'].'</font>' : '').
			  ($trace[$i]['con_info_addr'] ? '<br>Connection_Info_Address = <font color=green>'.$trace[$i]['con_info_addr'].'</font>' : '').
			  ($trace[$i]['mport'] ? '<br>Media_Port = <font color=green>'.$trace[$i]['mport'].'</font>' : '').
			  ($trace[$i]['mformat'] ? '<br>Media_Format = <font color=blue>'.$trace[$i]['mformat'].'</font>' : '').

			  ($trace[$i]['causei'] > 0 ? '<p><b>ISUP_Realse_Cause</b> = <font color=brown>'.$q850_arr[$trace[$i]['causei']].' ('.$trace[$i]['causei'].')</font>' : '');

		}	elseif(!strcmp($trace[$i]['type'],'dns')) {

			if(strlen($trace[$i]['query_name'])<=56 && strlen($trace[$i]['naptr_regex'])<=30) {
				$width = 350;
			} else if(strlen($trace[$i]['query_name'])<=70 && strlen($trace[$i]['naptr_regex'])<=45) {
				$width = 450;
			} else if(strlen($trace[$i]['query_name'])<=90 && strlen($trace[$i]['naptr_regex'])<=60) {
				$width = 550;
			} else {
				$width = 650;
			}
			$float_txt .=
				$width.
			  'px;"><i>Flow_No</i> : <b>'.($i+1).'</b><hr>'.
			  '<font color=darkred>'.$trace[$i]['enum_number'].'</font><p>'.
			  'Transaction_ID = <font color=green>'.$trace[$i]['transaction_id'].'</font>'.
			  ($trace[$i]['reply_code'] != "" ? '<br><b>Reply_Code</b> = <font color=brown>'.getDNSReplyCode($trace[$i]['reply_code']).' ('.$trace[$i]['reply_code'].')</font>' : '').
			  '<p>Queries_Name = <font color=green>'.$trace[$i]['query_name'].'</font>'.
			  ($trace[$i]['answer_name'] ? '<p>Answer_Name = <font color=red>'.$trace[$i]['answer_name'].'</font>' : '').
			  ($trace[$i]['naptr_service'] ? '<br>Answer_Service = <font color=darkpink>'.$trace[$i]['naptr_service'].'</font>' : '').
			  ($trace[$i]['naptr_regex'] ? '<br>Answer_Regex = <b><font color=blue>'.$trace[$i]['naptr_regex'].'</font></b>' : '');

		} elseif(!strcmp($trace[$i]['type'],'dia')) {

			if(strlen($trace[$i]['session_id'])<=56 && strlen($trace[$i]['public_id'])<=30) {
				$width = 350;
			} else if(strlen($trace[$i]['session_id'])<=70 && strlen($trace[$i]['public_id'])<=35) {
				$width = 450;
			} else if(strlen($trace[$i]['session_id'])<=90 && strlen($trace[$i]['public_id'])<=40) {
				$width = 550;
			} else {
				$width = 650;
			}
			$float_txt .=
				$width.
			  'px;"><i>Flow_No</i> : <b>'.($i+1).'</b><hr>'.
			  '<b>Command_Code</b> = <font color=darkred>'.$trace[$i]['cmd_code_detail'].' ('.$trace[$i]['cmd_code'].')</font>'.
			  '<br><b>Application_ID</b> = <font color=red>'.getApplicationId($trace[$i]['application_id']).' ('.$trace[$i]['application_id'].')</font><p>'.
			  'Session_ID = <font color=green>'.$trace[$i]['callid'].'</font>'.
			  ($trace[$i]['user_name'] ? '<br>User_Name = <font color=darkpink>'.$trace[$i]['user_name'].'</font>' : '').
			  ($trace[$i]['public_id'] ? '<br>Public_Identity = <font color=blue>'.$trace[$i]['public_id'].'</font>' : '').
			  ($trace[$i]['result_code'] > 0 ? '<br><b>Result_Code</b> = <font color=brown>'.getResultCode($trace[$i]['result_code']).' ('.$trace[$i]['result_code'].')</font>' : '').
			  ($trace[$i]['ex_result_code'] > 0 ? '<br><b>Exp_Result_Code</b> = <font color=brown>'.getExperimentalResultCode($trace[$i]['ex_result_code']).' ('.$trace[$i]['ex_result_code'].')</font>' : '');

		} elseif(!strcmp($trace[$i]['type'],'m2u')) {

			$ci = 0;
			if(!empty($q850_arr[$trace[$i]['cause_i']])) {
				$ci = strlen($q850_arr[$trace[$i]['cause_i']]);
			}
			if(!$trace[$i]['called'] && !$ci) {
				$width = 150;
				if(!strcmp($trace[$i]['type'],'m2u')) {
					$width = 250;
				}
			} elseif($trace[$i]['called']) {
				$width = 250;
			} else {
				$width = 350;
			}

			$float_txt .=
				$width.
			  'px;"><i>Flow_No</i> : <b>'.($i+1).'</b><hr>'.
			  '<b><font color=darkred>'.$trace[$i]['message_type'].' ('.$trace[$i]['msg_type'].')</font></b><p>';
			if(!strcmp($trace[$i]['type'],'m2u')) {
				$float_txt .= 
				  '<p><b>SRC_IP</b> = <font color=green>'.$trace[$i]['saddr'].'</font>'.
				  '<br><b>DST_IP</b> = <font color=green>'.$trace[$i]['daddr'].'</font>';
			}
			$float_txt .=
			  '<p><b>OPC</b> = <font color=blue>'.$trace[$i]['opc'].'</font>'.
			  '<br><b>DPC</b> = <font color=blue>'.$trace[$i]['dpc'].'</font>'.
			  '<br>SLS = <font color=green>'.$trace[$i]['sls'].'</font>'.
			  '<p><b>CIC</b> = <font color=blue>'.$trace[$i]['cic'].'</font>'.
			  ($trace[$i]['called'] ? '<br><b>Called Party Number</b> = <font color=blue>'.$trace[$i]['called'].'</font>' : '').
			  ($trace[$i]['calling'] ? '<br><b>Calling Party Number</b> = <font color=blue>'.$trace[$i]['calling'].'</font>' : '').
			  ($trace[$i]['redir'] > 0 ? '<br><b>Redirecting Number</b> = <font color=green>'.$trace[$i]['redir'].'</font>' : '').
			  ($trace[$i]['cause_i'] > 0 ? '<br><b>Realse_Cause</b> = <font color=brown>'.$q850_arr[$trace[$i]['cause_i']].' ('.$trace[$i]['cause_i'].')</font>' : '');

		}	elseif(!strcmp($trace[$i]['type'],'rtp')) {

			$width = 300;
			$float_txt .=
				$width.
			  'px;"><i>Flow_No</i> : <b>'.($i+1).'</b><hr>'.
			  ($trace[$i]['rtp_type'] ? '<font color=darkred>'.getPayloadType($trace[$i]['rtp_type']).'</font>' : '').
			  ($trace[$i]['rtp_seq'] ? '<br>Sequence number = <font color=blue>'.$trace[$i]['rtp_seq'].'</font>' : '').
			  ($trace[$i]['rtp_marker'] ? '<br><b><font color=darkgreen>Marker</font></b>' : '').
			  ($trace[$i]['rtp_timestamp'] ? '<br>Timestamp = <font color=green>'.$trace[$i]['rtp_timestamp'].'</font>' : '').
			  ($trace[$i]['rtp_ssrc'] ? '<br>SSRC = <font color=blue>'.$trace[$i]['rtp_ssrc'].'</font>' : '').
			  (array_key_exists('dtmf_num', $trace[$i]) ? '<br><b>DTMF</b> = <font color=blue><b>'.$trace[$i]['dtmf_num'].'</b></font>' : '').
				(array_key_exists('dtmf_num', $trace[$i]) ? '<br>End of Event = '. ($trace[$i]['dtmf_end'] ? 'True' : 'False') : '');
		}
    $float_txt .= '</div>\'';
	}
	print $float_txt;
?>
];

// 固定顯示左上方
function fixonTop(){
	var myleft, mytop;
  if (document.compatMode == "BackCompat") {
		myleft = document.body.scrollLeft;
		mytop = document.body.scrollTop;
  } else { //document.compatMode == \"CSS1Compat\"
		myleft = document.documentElement.scrollLeft == 0 ? document.body.scrollLeft : document.documentElement.scrollLeft;
		mytop = document.documentElement.scrollTop == 0 ? document.body.scrollTop : document.documentElement.scrollTop;
  }
	if(mytop > $('#mzpic').height()) {
		$('#pic_title').show();
		$('#pic_title').css('top',mytop);
	} else {
		$('#pic_title').hide();
	}
}

$(function() {
	$('area').popover({
    measure: 'img.image-map',
    mouseOffset: 20,
    container: 'body',
    followMouse: true,
    html: true,
    placement: function() {
    	var pos = window.innerHeight*5/8;
    	if(event.pageY > pos)
    		return 'top';
    	else
    		return 'right';
    },
    trigger: 'hover',
    content: function(){
    	return contents[$(this).data('id')];
    }
	});
});
window.onscroll=fixonTop;
</script>
</body>
</html>
