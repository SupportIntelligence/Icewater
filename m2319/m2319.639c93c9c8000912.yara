
rule m2319_639c93c9c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.639c93c9c8000912"
     cluster="m2319.639c93c9c8000912"
     cluster_size="6"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['2bf09a75caa14e3ccbb8773c5f3682ca','394958e8eec7e0fcc7fd4f9702ce3c91','940c491f1a7293727c0826aa41cdfe25']"

   strings:
      $hex_string = { 2e636f6d2f7265617272616e67653f626c6f6749443d3638373231373038313637313339353634393826776964676574547970653d426c6f6741726368697665 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
