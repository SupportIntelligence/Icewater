
rule n3e9_31144489c6210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.31144489c6210b12"
     cluster="n3e9.31144489c6210b12"
     cluster_size="8"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="graftor malicious bcak"
     md5_hashes="['0b82c8434e94ca5e74a08a813ac7ca9a','1ef68eb938afb4e178e78e205b9d9a67','eb5ce40ac210de3988c1550805a0dddf']"

   strings:
      $hex_string = { 772995ff0382b4507424ef14557d8697e0b5d0b74435caa2af58e562a9da04dcf7e783257576215fb66458b3b648faba0e3b2f1a86d2208c23a57b018b19ab57 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
