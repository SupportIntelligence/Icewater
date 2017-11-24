
rule k2321_291ced6d9a9b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.291ced6d9a9b0b12"
     cluster="k2321.291ced6d9a9b0b12"
     cluster_size="12"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy emotet"
     md5_hashes="['06b2704e3bc09ec1b9360a5e75bb5b1a','2ae73c3196153f9355e0c0dba1884ba3','ee95e6043573d1921288f91d6e65c744']"

   strings:
      $hex_string = { 9d1bc99a18c64a0f66a768b9911ab15eab54ca6502f2f6ba3f23a0adcff7990c0e9b25120ad40a4590461dac56e895d210b538522d8a510b633582588d304ec3 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
