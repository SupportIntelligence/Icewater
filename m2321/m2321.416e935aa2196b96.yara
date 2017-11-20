
rule m2321_416e935aa2196b96
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.416e935aa2196b96"
     cluster="m2321.416e935aa2196b96"
     cluster_size="32"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['03601480cf3f0d4e05a92465380cf384','0db60a43a4b37fb5462788e2c0729a10','8f39aa1dd94f5ed2c2381f158e4dc55f']"

   strings:
      $hex_string = { a0e43f75cac12da33a391321d38da6dd933e0dc7c0746864b1c5d452cb1f148172f2444c7fb985f2057840cd8e914602fa6fac112320bdc91d70808c7a5ab2bc }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
