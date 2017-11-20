
rule k2321_291ced6d94bb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.291ced6d94bb0b12"
     cluster="k2321.291ced6d94bb0b12"
     cluster_size="8"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="emotet tinba zusy"
     md5_hashes="['0163dc11a5635545bd7ceea8a0b23291','151a0020db968d9e36a4ce625bc30b94','e943d866516d971131083270db513c7e']"

   strings:
      $hex_string = { 5777f0fb1fb66eda347ecc98b8a8689d4221431216f0d552692032854a05b10049c8668b391cbd56dba7478f829933df7deb2d38e3a5a6464878f2e03ee876ff }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
