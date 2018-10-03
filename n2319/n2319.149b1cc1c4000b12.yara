
rule n2319_149b1cc1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.149b1cc1c4000b12"
     cluster="n2319.149b1cc1c4000b12"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="miner coinminer cryxos"
     md5_hashes="['83c9346afcc853c645df66561a631767ee9fdc2b','2144e62e4866cb83e5d411767f2c1f0255e5d972','d08fafab7899289d8b11676a662cbff07b81b667']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.149b1cc1c4000b12"

   strings:
      $hex_string = { 434f4e4649473d7b4c49425f55524c3a2268747470733a2f2f636f696e686976652e636f6d2f6c69622f222c41534d4a535f4e414d453a22776f726b65722d61 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
