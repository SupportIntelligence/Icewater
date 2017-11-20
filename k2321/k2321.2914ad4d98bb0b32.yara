
rule k2321_2914ad4d98bb0b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2914ad4d98bb0b32"
     cluster="k2321.2914ad4d98bb0b32"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy emotet tinba"
     md5_hashes="['3bf80e4b98d5f7e293212b144511f949','3c6cc2c3a36474886698dd3b899eee6d','dd236614124e0d9f69281e8e0038078c']"

   strings:
      $hex_string = { 5777f0fb1fb66eda347ecc98b8a8689d4221431216f0d552692032854a05b10049c8668b391cbd56dba7478f829933df7deb2d38e3a5a6464878f2e03ee876ff }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
