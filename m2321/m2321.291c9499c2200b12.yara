
rule m2321_291c9499c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.291c9499c2200b12"
     cluster="m2321.291c9499c2200b12"
     cluster_size="10"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal vjadtre wapomi"
     md5_hashes="['136a3192f784733138d6c816d31a15f2','23d06c03986773319d819bb608eae9e8','ce082f4bb20d9f15797110405b476a90']"

   strings:
      $hex_string = { 7c37e9a4ce3fe0f6423d497d76e73c08ca6516633da564ad2f5d104ef0ba77ff1af59af4d9854aea212481896dc2f11e6e801426a82353074dc550cf6a945cc7 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
