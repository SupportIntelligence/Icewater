
rule k2319_180d9ca9c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.180d9ca9c8000912"
     cluster="k2319.180d9ca9c8000912"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['12ac14ff002100be27d3db284eccc7b1b9418985','e97cede8afc8c869a235191a0d400e47ed1816cc','502e429d1e708e687f9e0fd86e80f6962fa5001d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.180d9ca9c8000912"

   strings:
      $hex_string = { 39293a2833332e3545312c30783631292929627265616b7d3b76617220733579303d7b27783630273a222b2f222c27723258273a66756e6374696f6e28472c54 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
