
rule p26bb_4b151220d9eb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p26bb.4b151220d9eb0912"
     cluster="p26bb.4b151220d9eb0912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="tofsee backdoor malicious"
     md5_hashes="['8f209ac95f418665db0c3d6bbf337d2b2b58b705','1a5b96a98f9adca5cf9a8dfa7309513b2e6c6bb5','93280018b9e56b2b6b5b2f75fdd3d2c17dce3ef8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=p26bb.4b151220d9eb0912"

   strings:
      $hex_string = { 16a5789827228dec58e53a91df433092d71fbed1a740b98ee6239c15b74c573149caac45745c96f901531c3702c5c19f4f5284b11005320694a34756aefab09e }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
