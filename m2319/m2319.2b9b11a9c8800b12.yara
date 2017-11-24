
rule m2319_2b9b11a9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2b9b11a9c8800b12"
     cluster="m2319.2b9b11a9c8800b12"
     cluster_size="13"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['098471821f2e3c6d5930b92fd8eea09f','0cbde999580c09917d1986a8426c7591','f34f5e7052204f35acdb0a098c05bc68']"

   strings:
      $hex_string = { 2e636f6d2f7265617272616e67653f626c6f6749443d3431373532353136393037333932343030343526776964676574547970653d426c6f6741726368697665 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
