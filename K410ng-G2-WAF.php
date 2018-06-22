<?php
error_reporting(0) ;

class waf{
    private $request_url;
    private $request_method;
    private $request_data;
    private $headers;
    private $raw;


function __construct(){
    $this->write_access_log_probably();
    $this->write_access_logs_detailed();
    if($_SERVER['REQUEST_METHOD']!= 'POST' && $_SERVER['REQUEST_METHOD'] != 'GET'){
        write_attack_log("method");
    }
    $this->request_url=$_SERVER['REQUEST_URI'];

    
    $this->request_data = file_get_contents('php://input');
    $this->headers=$this->get_all_headers();
    $this->filter_attack_keyword($this->filter_invisiable(urldecode($this->filter_0x25($this->request_url))));
    $this->filter_attack_keyword($this->filter_invisiable(urldecode($this->filter_0x25($this->request_data))));
    $this->detect_upload();
    $this->global_attack_detect();
}

function global_attack_detect(){
    foreach($_GET as $key=> $value){
        $_GET[$key] = $this->filter_dangerous_words($value);


    }
    foreach ($_POST as $key => $value){
        $_POST[$key] = $this->filter_dangerous_words($value);
    }
    foreach($headers as $key => $value){
        $this->filter_attack_keyword($this->filter_invisiable(urldecode(filter_0x25($value))));
        $_SERVER[$key   ] = $this->filter_dangerous_words($value);
    }
}

funcion detect_upload(){
    foreach($_FILES as $key=> $value){
        if($_FILES[$key]['size']>1){
            echo "upload file error";
            $this->write_attack_log("Upload");
            exit(0);

        }
    }
}

function write_access_log_probably(){
    $raw = date("Y/m/d H:i:s").'   ';
    $raw .= $_SERVER['REQUEST_METHOD'].'  '.$_SERVER['REQUEST_URI'].'   '.$_SERVER['REMOTE_ADDR'].'   ';
    $raw .= 'POST:'.file_get_contents('php://input')."\r\n";
    $ffff = =fopen('all_requests.txt','a');
    fwrite($ffff,$raw);
    fclose($ffff);
}

function write_access_logs_detailed(){
    $data = date("Y/m/d H:i:s")."--"."\r\n".$this->get_http_raws()."\r\n\t\n";
    $ffff = fopen('all_requests_detail.txt','a');
    fwrite($ffff,urldecode($data));
    fclose($ffff);

}

function get_all_headers(){
    $headers = array();
    foreach($_SERVER as $key => $value){
        if(substr($key,0,5) === 'HTTP_'){
            $headers[$key] = $value;
        }
    }
    return $headers;
}

function filter_invisiable($str){
    for($i=0;$i<strlen($str);$i++){
        $ascii = ord($str[$i]);
        if($ascii>126 || $ascii < 32){
            if(!in_array($ascii,array(9,10,13))){
                write_attack_log("interrupt");
            }else{
                $str = str_replace($ascii,"",$str);
            }
            }
        }
        $str = str_replace(array("`","|",";",")"," " ,$str);
        return $str;
    }


    function filter_0x25($str){
        if(strpos($str,"0x25") !== false){
            $str = str_replace("%25","%",$str);
        }else{
            return $str;
        }
        }
function filter_attack_keyword($str){
    if(preg_match"/select\b|insert\b|update\b|drop\b|and\b|delete\b|dumpfile\b|outfile\b|load_file|rename\b|floor\(|extractvalue|updatexml|name_const|multipoint\(/i", $str)){
        $this->write_attack_log("sqli");
}
    if(substr_count($str,$_SERVER['PHP_SELF'])<2){
        $tmp = str_replace($_SERVER['PHP_SELF'],"",$str);
        if(preg_match("/\.\.|.*\.php[35]{0,1}/i",$tmp)){

            $this->write_attack_log("LFI/LFR");;

        }


    }else{
        $this->write_attack_log("LFI/LFR");

    }
    if(preg_match("/base64_decode|eval\(|assert\(|file_put_contents|fwrite|curl|system|passthru|exec|system|chroot|scandir|chgrp|chown|shell_exec|proc_open|proc_get_status|popen|ini_alter|ini_restorei/i", $str)){
        $this->write_attack_log("EXEC");
    }
    
    if(preg_match("/flag/i",$str)){
        $this->write_access_log("GETFLAG");
    }

}

function filter_dangerous_words($str){
    $str = str_replace("'","'",$str);
    $str = str_replace("\"", "“", $str);
    $str = str_replace("<", "《", $str);
    $str = str_replace(">", "》", $str);
    return $str;
}

function get_http_raws(){
    $raw = '';
    $raw .= $_SERVER['REQUEST_METHOD'].''.$SERVER['REQUEST_URI']' '.$_SERVER['SERVER_PROTOCOL']."\r\n";
    foreach($_SERVER as $key=> $value){
        if(subst($key,0,5) === 'HTTP_'){
            $key = substr($key,5);
            $key = str_replace('_','-',$key);
            $raw .= $key.':'.$value."\r\n";
        }
    }
    $raw .= "\r\n";
    $raw .= file_get_contents('php://input');
    return $raw;


}

function write_attack_log($alert){
    $date = date("Y/m/d H:i:s")." -- [".$alert."]"."\r\n".$this->get_http_raws()."\r\n\r\n";
    $ffff = fopen('attack_detected_log.txt','a');
    fwrite($ffff,$data);
    fclose($ffff);
    if($alert == 'GETFLAG'){
        echo ' CTF{YOU_ARE_GOOD}';

    }else{
        sleep(3);
    }
    exit(0);
}
$waf = new waf();
?>