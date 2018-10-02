
rule j3f8_5e1b466a9432f914
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.5e1b466a9432f914"
     cluster="j3f8.5e1b466a9432f914"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos jisut boogr"
     md5_hashes="['fb14a00e0dfb127a860ae5346434c08fe35729f2','7387da057118066c40c1bf61b12fee39938e05f8','c9fc8df4cf4b49945cc23929304f57ee5a209a7a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j3f8.5e1b466a9432f914"

   strings:
      $hex_string = { 61676572244e616d654e6f74466f756e64457863657074696f6e3b001a4c616e64726f69642f6f732f4275696c642456455253494f4e3b000753444b5f494e54 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
