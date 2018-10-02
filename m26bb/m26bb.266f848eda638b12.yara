
rule m26bb_266f848eda638b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.266f848eda638b12"
     cluster="m26bb.266f848eda638b12"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore ccmw classic"
     md5_hashes="['45934f5cc8a6d9f876121b1b3825fdd045361259','d09afa96bc6ee7373cff3d132beee840b83a799a','6b04d95daee61c62f3548e7d3b24a469bf25c8e5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.266f848eda638b12"

   strings:
      $hex_string = { 6f5fdced098980629f15e25526ea5348e9f2d50e3f7f6ce0de7573fc3d60d778b3feef45ebff814250f011fd0ccca49770a7e1f90a184438a59da247e620bd08 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
