
rule n26bb_47266d6caa211932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.47266d6caa211932"
     cluster="n26bb.47266d6caa211932"
     cluster_size="21"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="virut malicious patched"
     md5_hashes="['45fb2d09858e5a0b128dafa638ab1d69aa8944c7','767d97bfa48a281e2b043bb137c286ad24f8dca9','d5ddfcbaf4c3f3d67c8ca455a4063f96ea33676c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.47266d6caa211932"

   strings:
      $hex_string = { c97cef8b7d1085ff74e88b063bc774323b4d147e186a025150ff1538a3040183c40c85c0752c680e000780ebca50ff15ec15000159893e833e005f5e74e85dc2 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
