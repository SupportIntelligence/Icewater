
rule k2321_0935a42dda9af936
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0935a42dda9af936"
     cluster="k2321.0935a42dda9af936"
     cluster_size="42"
     filetype = "gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre wapomi"
     md5_hashes="['057b7b1246f00f53ea25b1891c20c151','0742ab1c782d6932d7a824e9d5b75323','5087652ff0441572433cdb3f3bc30196']"

   strings:
      $hex_string = { 4fa3ff16c96c43d731847699f3ad87fe3439c54e4f6b8d64b7cb4c37e99bc059a9f54dccf6047ce0c6f76b413e62de9dfc29afdf5f2a60ca9a26cd38733bc3ef }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
