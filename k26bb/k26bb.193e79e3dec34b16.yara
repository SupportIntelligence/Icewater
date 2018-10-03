
rule k26bb_193e79e3dec34b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.193e79e3dec34b16"
     cluster="k26bb.193e79e3dec34b16"
     cluster_size="1691"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore dealply malicious"
     md5_hashes="['011a49eaec722c106491b3672cc6c00081f7b730','2814e377c4dff51d504aab82aac46d6f8fe40adf','5788aaa17a94cac3c5b05188a37ee42f4cb404a9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.193e79e3dec34b16"

   strings:
      $hex_string = { 6120697320636f72727570746564202825642900005383c4f88bd8891c24c64424040b546a00b9187e4000b201b8c8774000e8aedaffffe8a9b0ffff595a5bc3 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
