
rule m2321_0691534b2b1b2321
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0691534b2b1b2321"
     cluster="m2321.0691534b2b1b2321"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar midie scudy"
     md5_hashes="['0b79bf98c5754defe299d8a20b59a85b','5f53dfbe397b7f7e828116dc48b97482','f9b9a5926432e3732afb0a1bcbb4093e']"

   strings:
      $hex_string = { 3785aa904d662e0af1dd9b5805d4adac99316b8e5c9e0f23ab873ca53e427b8da6b4be16f603f971fd8c6080020e38119491e53db7d0d9a1bc6a786cc9a8349a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
