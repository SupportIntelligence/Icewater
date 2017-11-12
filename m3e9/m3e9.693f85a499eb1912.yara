
rule m3e9_693f85a499eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.693f85a499eb1912"
     cluster="m3e9.693f85a499eb1912"
     cluster_size="265"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod autorun"
     md5_hashes="['0127de1b0e910735def4341bfd1e1e5e','043b1e87641eacc8ff2ed350cc52ceaf','416efc1e1873853bfb97119916ceda8c']"

   strings:
      $hex_string = { 92b933ebd2f3d2d83b03bf9f5de75525223876b80932cf8a0e9bd1bd4d5730d2d5d5ba4997862aa0d1a483dd67cbe3efa992aabbdb000fe150e357507d3d9d44 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
