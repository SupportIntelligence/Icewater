
rule p26d7_4b24ea48c0000916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p26d7.4b24ea48c0000916"
     cluster="p26d7.4b24ea48c0000916"
     cluster_size="255"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="gamemodding malicious gamehack"
     md5_hashes="['757cfd1b569b1daf833c8d76d200e0d5f4768d59','b277e4c8429e5c5a47eac8b5a7d43d649888265d','ae18b97cf5f34462df2abf64bb70e0024e9e6d2e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=p26d7.4b24ea48c0000916"

   strings:
      $hex_string = { d6fcff9fd3fbfe97cffaff85bbe5ff4a6b84ff151f27ff010202fd000000e80b1117832540542405090d6a010203e6203f55ff51a1deff56b3f8ff52b1f7ff4e }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
