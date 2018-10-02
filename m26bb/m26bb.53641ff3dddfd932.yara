
rule m26bb_53641ff3dddfd932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.53641ff3dddfd932"
     cluster="m26bb.53641ff3dddfd932"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore malicious attribute"
     md5_hashes="['3f1f9d45901e7001c5c3378cfc61b4504f1d904e','ed1a8664c73c35259919127e0b5c9374b3397f9f','0f039c6190ab75d0329537c6256badb1ba072486']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.53641ff3dddfd932"

   strings:
      $hex_string = { d0c516e093ad4f430044b48f9234fa568a9cd903b1056042d5f7b72164145331fc9f49488d6ba1cae18139ce5f332cf65861d3db98173d6c7f09dee60b3bf8fe }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
