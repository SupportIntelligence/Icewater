
rule k2319_39199eb9ca800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.39199eb9ca800932"
     cluster="k2319.39199eb9ca800932"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['1df018825a36f23e5c81c66fea6d574337119f49','e1a4f5467a13ec844a11739821991640beff8aca','bf7f8731e10d74eb4cb2d1a83bfc75fd2dfeae3b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.39199eb9ca800932"

   strings:
      $hex_string = { 39303045332c362e30374532292929627265616b7d3b7661722073385a36333d7b274c3776273a2265617465222c27743733273a66756e6374696f6e28532c4c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
