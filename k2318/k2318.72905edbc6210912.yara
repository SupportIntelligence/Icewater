
rule k2318_72905edbc6210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.72905edbc6210912"
     cluster="k2318.72905edbc6210912"
     cluster_size="2028"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['c5daf71e6782bb1e7a740aafe913172a683a6163','9a85cd609cf3b90cd8dddeafb511b534045856b5','354723a7fff21cd5cb44a018151f25cef41ed04d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.72905edbc6210912"

   strings:
      $hex_string = { e0e1e5f2e8f7edeebf20e4b3baf2e8202831e320eaf0e8f1f2e0ebb3f7edeee3ee20f6f3eaf0f320e2b3e4efeee2b3e4e0ba20302c3120d5ce292e0d0a0d0ac2 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
