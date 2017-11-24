
rule m2319_6b0fb1e9ca000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.6b0fb1e9ca000912"
     cluster="m2319.6b0fb1e9ca000912"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker script"
     md5_hashes="['26602a4e030b6d9da18b8ed2e9c2fedc','d97cbccf9555f2e858b55bb827a03be7','f9d91c2ccb68c8865300fa04ccc1ba78']"

   strings:
      $hex_string = { 722e636f6d2f7265617272616e67653f626c6f6749443d3638373231373038313637313339353634393826776964676574547970653d426c6f67417263686976 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
