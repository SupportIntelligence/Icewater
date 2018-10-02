
rule n231d_11b0dc5bdee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.11b0dc5bdee30912"
     cluster="n231d.11b0dc5bdee30912"
     cluster_size="77"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hiddad androidos hiddenads"
     md5_hashes="['ddc6e7407a448dd130ab32c61c180fc7fd4254a0','bb61400ac3afc80548e3b86ed4de38c83ee23a0f','3b5f6c3580e75aa2154cc0b1e5f63cda39f7f21e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.11b0dc5bdee30912"

   strings:
      $hex_string = { da6db6889474278ce0deef86d5dd26a7f4d1673f7cf6e2e3ffe97ffc1f52b99dc5d004315553238418385b1532365eca7ed34381d9ac3b3e3c6ce6ed2e0dabcd }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
