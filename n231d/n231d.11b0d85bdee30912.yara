
rule n231d_11b0d85bdee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.11b0d85bdee30912"
     cluster="n231d.11b0d85bdee30912"
     cluster_size="338"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hiddad androidos andr"
     md5_hashes="['31b6bd591a5e27975f31b08ae2ac9618617ccf9f','bc625a27026cc17faef79672afc8e8e1895c67df','6e8e371a8d8c2d3dbd2081f1d10e14e776df555a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.11b0d85bdee30912"

   strings:
      $hex_string = { da6db6889474278ce0deef86d5dd26a7f4d1673f7cf6e2e3ffe97ffc1f52b99dc5d004315553238418385b1532365eca7ed34381d9ac3b3e3c6ce6ed2e0dabcd }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
