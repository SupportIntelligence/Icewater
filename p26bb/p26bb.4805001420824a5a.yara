
rule p26bb_4805001420824a5a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p26bb.4805001420824a5a"
     cluster="p26bb.4805001420824a5a"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious tofsee backdoor"
     md5_hashes="['86ebd25da4a1bf78f87d1682e3ecedafb604097c','fb2edf647a8606978fb547ed4b5b1df1cf0507e5','1a3d97e620f1aec301e74c2f975d4d7bc640ad21']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=p26bb.4805001420824a5a"

   strings:
      $hex_string = { 16a5789827228dec58e53a91df433092d71fbed1a740b98ee6239c15b74c573149caac45745c96f901531c3702c5c19f4f5284b11005320694a34756aefab09e }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
