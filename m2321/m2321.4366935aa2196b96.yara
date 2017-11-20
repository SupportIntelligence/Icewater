
rule m2321_4366935aa2196b96
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.4366935aa2196b96"
     cluster="m2321.4366935aa2196b96"
     cluster_size="41"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['03df96a7c8906f5073b7abd4afafe4e6','07fb59a836c2c32ea54595ace2cef581','6b74e8b9df3f19489ac1d9e799a3df81']"

   strings:
      $hex_string = { a0e43f75cac12da33a391321d38da6dd933e0dc7c0746864b1c5d452cb1f148172f2444c7fb985f2057840cd8e914602fa6fac112320bdc91d70808c7a5ab2bc }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
