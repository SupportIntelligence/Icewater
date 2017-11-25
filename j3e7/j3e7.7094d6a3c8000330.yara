
rule j3e7_7094d6a3c8000330
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e7.7094d6a3c8000330"
     cluster="j3e7.7094d6a3c8000330"
     cluster_size="11"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos aopkjho"
     md5_hashes="['1b1d31b6cb43b5077b49d875274522ca','321d7d20ff22260b0038c465538aeb9c','dab5c852c18b78252611160433eead35']"

   strings:
      $hex_string = { 6e672f436c6173734c6f616465723b00154c6a6176612f6c616e672f457863657074696f6e3b00124c6a6176612f6c616e672f4f626a6563743b00124c6a6176 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
