
rule m2321_539a96c9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.539a96c9cc000b12"
     cluster="m2321.539a96c9cc000b12"
     cluster_size="7"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['1d3b7432c0cfd4b77a076d260754cff6','2c295909c6cc89a6f8dcfab95bc3a7c8','ecab075ef63c33778619c172b6f71c29']"

   strings:
      $hex_string = { 5ec22394e28bb98e9eaca9b46d74736bbbe1f40a0224342bccf328ca717bcbaf62c8592904335bed1492729cd71500543ee051ab9097b635c703bccdf0eab038 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
