
rule k2319_181a9ca9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.181a9ca9c8800912"
     cluster="k2319.181a9ca9c8800912"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['36a435e4117251cd624a38f26c300e5508b49983','6e73a47e820ddf1e67236262e4a6924b67ab1cfb','d32ee63ed3a570effc4ee4d090ce42ae32ac46d3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.181a9ca9c8800912"

   strings:
      $hex_string = { 646f773b666f72287661722056324620696e206136543246297b6966285632462e6c656e6774683d3d3d282837392c35342e304531293e3d35322e3f28307833 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
