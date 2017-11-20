
rule k2321_6b1f17b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.6b1f17b9c8800b12"
     cluster="k2321.6b1f17b9c8800b12"
     cluster_size="10"
     filetype = "gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="waski ipatre upatre"
     md5_hashes="['1272c9e95483b5518d0c44d941054833','25961f30c8d43e4193d90998c9ea851a','f712b154fc0bfc944a1a93611d530339']"

   strings:
      $hex_string = { e5cc3ad2eb2c62d1002a0b915f8cb446ce8f11c8a9a6b1f4a0a4140d55286b85b71fd64a2680dc814288ba0f6d1636b68d82ce926c383da81d61e11cf0739aab }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
