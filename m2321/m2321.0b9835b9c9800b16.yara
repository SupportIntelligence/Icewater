
rule m2321_0b9835b9c9800b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0b9835b9c9800b16"
     cluster="m2321.0b9835b9c9800b16"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut shodi zusy"
     md5_hashes="['046ac35141d5e43f291c32b97c58c598','67ff39d73657b8a839c72524cbaa3acd','f52a4eed5b6d89184b6927d65ed551aa']"

   strings:
      $hex_string = { 03adc52f6b3772aa265609fa76bdf3688a424428e981afd16fd9110190d8997c934b1306bf9ffc86f9078b5bf0ef0f496087c0dbe00d97585d9885430b461e61 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
