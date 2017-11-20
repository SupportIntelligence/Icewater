
rule k2321_6b1f17a9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.6b1f17a9c8800b12"
     cluster="k2321.6b1f17a9c8800b12"
     cluster_size="12"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="waski ipatre upatre"
     md5_hashes="['1e961b02ee3417d6ff02b85af464d52b','2c2178c349a802cdcc7d9b708f39fbc6','e300c682e7da10c14f12f18ce1c1a5db']"

   strings:
      $hex_string = { e5cc3ad2eb2c62d1002a0b915f8cb446ce8f11c8a9a6b1f4a0a4140d55286b85b71fd64a2680dc814288ba0f6d1636b68d82ce926c383da81d61e11cf0739aab }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
