
rule m3e9_13c87a41c8000132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13c87a41c8000132"
     cluster="m3e9.13c87a41c8000132"
     cluster_size="21"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre ipatre kryptik"
     md5_hashes="['24bd653da9a898c3e70d90db45c21c6a','373b800decd948c452f6db2b80760086','db16b4ebb734ff4135160af1dceae875']"

   strings:
      $hex_string = { 3524a040005353ff751450ff750cff7508ffd63bc38945f8750733f6e9b70000007e3d83f8e0773883c0083d000400007716e89a0a00008bfc3bfb74ddc707cc }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
