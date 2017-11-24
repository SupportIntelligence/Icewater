
rule m3e9_10d2cfa9c2000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.10d2cfa9c2000912"
     cluster="m3e9.10d2cfa9c2000912"
     cluster_size="15"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys changeup"
     md5_hashes="['031cbc25f6b854238e968d549a2f85b3','2446dcc6de906e71c8581432155fb43f','ff033849b6de5b9e716f4320bfab3552']"

   strings:
      $hex_string = { 1918605b395865655d859ba7d4ae9f6f68695435004f535393f3e8e8f847240000000000000000000000008cf6f9f9ff03ff898898949261908d858f91b0aeab }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
