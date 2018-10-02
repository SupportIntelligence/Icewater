
rule m231b_4b5b3949c0000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m231b.4b5b3949c0000912"
     cluster="m231b.4b5b3949c0000912"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="clicker faceliker heuristic"
     md5_hashes="['cac7f23a18aa0d0f4db6c3eb3e95c8bcfabedc2b','9e787db23c2ac6da4858163402b9ff98d0bb1323','44370fa1c5aea67f7c705a5b2909419231ec6d63']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m231b.4b5b3949c0000912"

   strings:
      $hex_string = { 2d74573069427a4e6345716f2f554c6a544c594d595458492f41414141414141414731672f66436575396c336c696a302f733639382f626f6479777261705f62 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
