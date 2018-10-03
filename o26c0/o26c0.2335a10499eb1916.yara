
rule o26c0_2335a10499eb1916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c0.2335a10499eb1916"
     cluster="o26c0.2335a10499eb1916"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy gamehack injector"
     md5_hashes="['4d90c4ddba3d76f7e9f002feaaa42be77023e0e1','afb40aad18dd52945dcbfad4b4c1937691bdef36','17ce1e0c5ad75fc2d13a18e0f53c3062727dbdf1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c0.2335a10499eb1916"

   strings:
      $hex_string = { 580590990c108b45080f2f402076728d4df0e8c768ffff8d4df05169550ce80300006b45fc288d8c023488101051e87b0e090083c4080fb6d085d274446850d0 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
