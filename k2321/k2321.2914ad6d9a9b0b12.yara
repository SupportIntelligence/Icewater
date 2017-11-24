
rule k2321_2914ad6d9a9b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2914ad6d9a9b0b12"
     cluster="k2321.2914ad6d9a9b0b12"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba emotet zusy"
     md5_hashes="['01050e69d1437c5998ffe3bddcf35014','2fd6091b18dabedc2c9b959fc0f8f01f','90bdf3b44fe0f14714fa47bb54a70384']"

   strings:
      $hex_string = { 9d1bc99a18c64a0f66a768b9911ab15eab54ca6502f2f6ba3f23a0adcff7990c0e9b25120ad40a4590461dac56e895d210b538522d8a510b633582588d304ec3 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
