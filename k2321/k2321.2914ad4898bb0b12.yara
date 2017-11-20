
rule k2321_2914ad4898bb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2914ad4898bb0b12"
     cluster="k2321.2914ad4898bb0b12"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy emotet tinba"
     md5_hashes="['05c11499801599b039dffc88b75b8b0b','22269eb5201f9ae41bff2ecb318bdb7a','fc7e2f6d5331ebe44faf2c088f9a2f8a']"

   strings:
      $hex_string = { 52386f103d393b06b2770ce0ece8cfde3580f5463fe6963eecf989bca9d1e2d4486d7c7890d1a057c865221e97c761b65faff3b8702c9d561b6a088837aa930d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
