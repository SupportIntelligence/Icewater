
rule m26bb_1ec05d92894bd188
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.1ec05d92894bd188"
     cluster="m26bb.1ec05d92894bd188"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kazy malicious multiplug"
     md5_hashes="['5219db8d2da14a9c5865cfa423a6fc7176c90337','d3569f29b19b1285926725864ff6596c37614c20','a36542f827c626040ea7d704e0bf2b9d99204bda']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.1ec05d92894bd188"

   strings:
      $hex_string = { c746b59ab8299e50ec0376d7b7c1a9867f884ce23335247a28ca78fd3e274b5680bf1770256140944ff61c1134a1a0063d8f5e1c1ab213ac14896dba92ee09ed }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
