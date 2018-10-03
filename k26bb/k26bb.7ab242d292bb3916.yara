
rule k26bb_7ab242d292bb3916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.7ab242d292bb3916"
     cluster="k26bb.7ab242d292bb3916"
     cluster_size="237"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="defaulttab bundler malicious"
     md5_hashes="['b18903d0086d38c3adac30293d3532a217a17ea1','aca9dce8f3adb2a6f8e3c187c1e152ca943ea817','0789b318eb72379e3b8f4f897952a291e6e6daae']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.7ab242d292bb3916"

   strings:
      $hex_string = { 01999184059d958a2dc2bdb58fe0ddd9d1f4f3f2fbf5f5f3ffb9d3c5ffa0dbc3ffa0dbc2ffb3cdbeffebe9e8ffece9e9fdd8d5d0d3bfb9b291a0988b2f9a9285 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
