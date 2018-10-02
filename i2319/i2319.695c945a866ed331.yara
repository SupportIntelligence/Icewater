
rule i2319_695c945a866ed331
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2319.695c945a866ed331"
     cluster="i2319.695c945a866ed331"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script injector"
     md5_hashes="['8994db0f3495c1b008318b097299b06a3829a3de','c6bb55dced49b035314510298171e70be52e2311','1b4c6954455da10dece9a791e23d4c96cac3db99']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=i2319.695c945a866ed331"

   strings:
      $hex_string = { 6d6528292b36302a632a36302a316533293b76617220653d22657870697265733d222b642e746f555443537472696e6728293b646f63756d656e742e636f6f6b }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
