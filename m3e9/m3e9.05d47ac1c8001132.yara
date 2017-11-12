
rule m3e9_05d47ac1c8001132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.05d47ac1c8001132"
     cluster="m3e9.05d47ac1c8001132"
     cluster_size="304"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre ipatre kryptik"
     md5_hashes="['06e05f33c770311bc52556387354ea30','09923ba22bd402d0478ade2e7c5d2593','38a75a6aa81c2d5fc346e3263140f86d']"

   strings:
      $hex_string = { 6a01ff7520ffd685c00f84e20000008b3520a04000535357ff75f4ff750cff7508ffd68bc83bcb894df80f84c100000066f7450c00047429395d1c0f84b00000 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
