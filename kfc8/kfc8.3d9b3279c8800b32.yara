
rule kfc8_3d9b3279c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=kfc8.3d9b3279c8800b32"
     cluster="kfc8.3d9b3279c8800b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="infostealer banker androidos"
     md5_hashes="['63986451b3a023d6e760a70ed7c843d1800d0666','6049d73a452e39a69576efc180e93f7a8771686b','aeb6009c736b1c23f9bb1371ed78940afd30cf93']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=kfc8.3d9b3279c8800b32"

   strings:
      $hex_string = { d9f21ee235b505ef29d7176203f670811389f058f809b13e9f1f1877491b151fb82f31d6b47d8023de2b9c4a6def69b9c2b8613fe6ea39d78e885fe01df992b6 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
