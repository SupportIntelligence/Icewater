
rule n2319_5adb15adc2220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.5adb15adc2220b32"
     cluster="n2319.5adb15adc2220b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinminer"
     md5_hashes="['c5f52efb18a0ebb885186449fbf0c741dd031961','da2410a24d1e58ae252c0dcb046a9c987e6e6c76','a3762a1f2d75caac661751aa321f92b63fe10c21']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.5adb15adc2220b32"

   strings:
      $hex_string = { 313032343b766172204d41585f5441424c455f53495a453d4d6f64756c655b5c227761736d4d61785461626c6553697a655c225d3b696628747970656f662057 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
