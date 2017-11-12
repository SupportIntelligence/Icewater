
rule m3e9_6b2f25a4d9eb1b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6b2f25a4d9eb1b12"
     cluster="m3e9.6b2f25a4d9eb1b12"
     cluster_size="218"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod autorun"
     md5_hashes="['0256980d7603c9d8afd267b1915c52b3','0a0ece5a396c47d6fdba816a22edc53c','58e89a354372f080be5e4fee3426e49f']"

   strings:
      $hex_string = { 92b933ebd2f3d2d83b03bf9f5de75525223876b80932cf8a0e9bd1bd4d5730d2d5d5ba4997862aa0d1a483dd67cbe3efa992aabbdb000fe150e357507d3d9d44 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
