
rule o3e9_3498e448c4010b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.3498e448c4010b32"
     cluster="o3e9.3498e448c4010b32"
     cluster_size="743"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['000393cf50a8b038ee04958d8d026176','0072fc3b86efedd6f441848dfaf7462b','05cf753c4b61867896273f66482ff88c']"

   strings:
      $hex_string = { e7e700e4f0f000b0c4c70090a9ad0066ccff006699cc0099ccff00c6d6ef00ffffff00fefefe00fcfcfc00f8f8f800f1f1f100eaeaea00e3e3e300dddddd00d7 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
