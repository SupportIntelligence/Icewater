
rule o422_11e916c2c8001132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o422.11e916c2c8001132"
     cluster="o422.11e916c2c8001132"
     cluster_size="267"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bitminer bitcoinminer coinminer"
     md5_hashes="['c077c4bc37fb10e0f03a13199fc2b5d6da22fb5d','5cf57d36fda825171a1685ea404cb27968640046','5f0ffb8ae00df65dbffce386f84b11633a398209']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o422.11e916c2c8001132"

   strings:
      $hex_string = { 0310b6f003009af30310a5f30310d1f70310eff70310d8fb0310f6fd0310e6000410a0090400df0a041081110400f91404108b150410b9150410c4180400c11b }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
