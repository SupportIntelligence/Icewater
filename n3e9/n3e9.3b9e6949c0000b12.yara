
rule n3e9_3b9e6949c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.3b9e6949c0000b12"
     cluster="n3e9.3b9e6949c0000b12"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious dealply susp"
     md5_hashes="['2484e7bd9096c3c43398c888654279b3','427fed2816294518774061915e96d020','af76141d5c3960d658bdb2fd3b3e806a']"

   strings:
      $hex_string = { 004578697450726f63657373000000526567466c7573684b6579000000496d6167654c6973745f416464000000536176654443000056617269616e74436f7079 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
