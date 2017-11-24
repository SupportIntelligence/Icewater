
rule m2321_0b9e17c9cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0b9e17c9cc000b16"
     cluster="m2321.0b9e17c9cc000b16"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['27ce76ccf88b2362e9e73e682f4f51f6','78bab450c5489fcc2d834d6fe024d16e','fe6497a9df4008c894a9ddfa7820c3de']"

   strings:
      $hex_string = { aed753dcbd2070135a71c2c8a90add23066fb53b76412a7dcd37804397ffe945332f5d1bbfdf5f969ad1ef44037a6d51a403847ca6faf8b6d350f9e287489046 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
