
rule j26bf_18966cccc2230b30
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.18966cccc2230b30"
     cluster="j26bf.18966cccc2230b30"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dotdo genx malicious"
     md5_hashes="['2b3b891e03eec825e13311164c1a439421d3d76c','6db3ceab21dbe1214b340029950d4442e3cbddf0','b0689c4699c524eade6ffe8577405229f11de912']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.18966cccc2230b30"

   strings:
      $hex_string = { 7946696c6556657273696f6e417474726962757465004e65757472616c5265736f75726365734c616e67756167654174747269627574650053797374656d2e44 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
