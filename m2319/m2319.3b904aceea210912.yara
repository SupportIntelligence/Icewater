
rule m2319_3b904aceea210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3b904aceea210912"
     cluster="m2319.3b904aceea210912"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="clicker faceliker script"
     md5_hashes="['3d4500caf2e2fd0996602157e5e09162','676691a8a7e85a8ad0cf2169d1e08229','a2b10eecb9346f6759694fe7356f62ed']"

   strings:
      $hex_string = { 2e636f6d2f7265617272616e67653f626c6f6749443d36303730313834373436333236323539343126776964676574547970653d4c6162656c26776964676574 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
