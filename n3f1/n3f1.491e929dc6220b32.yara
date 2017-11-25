
rule n3f1_491e929dc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f1.491e929dc6220b32"
     cluster="n3f1.491e929dc6220b32"
     cluster_size="17"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="obfus androidos andr"
     md5_hashes="['107e187dc5e9d318170b54e429300b65','1636f7a1c078505fe3328fef212d4c51','f6b8eeef3b0eb93217db599c1212fc71']"

   strings:
      $hex_string = { 13eca878672d501987aa3673c7ff7bf7eec51bdef07a48dd0fc25eb52fa409158cd6410a05535b98dac21a86ef9d12f8fce7ff712e88703aad90e539a6551dea }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
