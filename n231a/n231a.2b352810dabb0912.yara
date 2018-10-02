
rule n231a_2b352810dabb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231a.2b352810dabb0912"
     cluster="n231a.2b352810dabb0912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="faaf eeaf obfuscator"
     md5_hashes="['39cb85017549ab46fd221ff2f399e2ae3dc6b0bf','aa78a29101e6da447820cb05203959a9e38b77ae','9fea3cf371cf20d7adfe97ffcd4c1be5441bb4ca']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231a.2b352810dabb0912"

   strings:
      $hex_string = { 59d5463bbd1da38f396d29d12417d77fb5c215ede1fda069e841a99e628979eb33353f81932ec5dc5fd87bdbfc571054a721c0cd05ac08f84fc3c6400f7afe3d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
