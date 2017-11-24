
rule k2321_2934ad6d989b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2934ad6d989b0b12"
     cluster="k2321.2934ad6d989b0b12"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy vbkrypt"
     md5_hashes="['938200a266b8491e05b010a2388bc8c9','cbbc351e6349faecfb4676df40e42716','fc5e14d38bd6767cab12bd3a72b01bf1']"

   strings:
      $hex_string = { 4dc8b43b44dfec09f602eb8485e85b3255fa6592f60572b389368b0e605df86881018869ae1aa36fb67f62db6cd57cab401f9c4e76cecd24ec979b4174b5e4ca }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
