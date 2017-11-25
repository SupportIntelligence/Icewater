
rule m2321_091e95a9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.091e95a9c8800b32"
     cluster="m2321.091e95a9c8800b32"
     cluster_size="12"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar virtob shyape"
     md5_hashes="['09e392e20de1217168fd1564ed644499','241819d6517a3f36aba1d307299fe082','fbef7690eecb67088adfbd9d45c35099']"

   strings:
      $hex_string = { 97b90feb87188af07125884b2dad320ca86fe3742b949be58d6b90d80bd393ef516a8f84bd14dc821cbf64a0b10aa3949fe1a6b5651b6efd452461b091b4c1ee }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
