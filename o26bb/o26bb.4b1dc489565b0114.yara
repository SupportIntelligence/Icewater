
rule o26bb_4b1dc489565b0114
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.4b1dc489565b0114"
     cluster="o26bb.4b1dc489565b0114"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="barys malicious heuristic"
     md5_hashes="['85e35d730068336239a3a23193b43a134b059d51','7bd8d2516e659a4dc5c1fcd7d50e7a2856336f23','c50a0a2c7d959abfdf4fde37944c0ba993590ac1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.4b1dc489565b0114"

   strings:
      $hex_string = { 8d46185750e881c1ffff895e0483c40c33db89be1c02000043395de8764f807dee008d45ee74218a480184c9741a0fb6d10fb608eb06804c0e1904413bca76f6 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
