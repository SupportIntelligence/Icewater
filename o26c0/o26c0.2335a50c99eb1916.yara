
rule o26c0_2335a50c99eb1916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c0.2335a50c99eb1916"
     cluster="o26c0.2335a50c99eb1916"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy gamehack injector"
     md5_hashes="['71dacae73ea3dd708ca02e698b9fdec20a0298a6','0b52751d7382b0a7b60a0bf14e878a524ef891d1','d9b54dc325404aa616ee3cb5afb5731c6a1ca293']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c0.2335a50c99eb1916"

   strings:
      $hex_string = { 580590990c108b45080f2f402076728d4df0e8c768ffff8d4df05169550ce80300006b45fc288d8c023488101051e87b0e090083c4080fb6d085d274446850d0 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
