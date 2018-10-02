
rule p26d7_13334cc344000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p26d7.13334cc344000b12"
     cluster="p26d7.13334cc344000b12"
     cluster_size="151"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious attribute engine"
     md5_hashes="['7b9e3c0c7bf057664e9e6588ad6142359d8ce69a','291923d1477c21b001a9e3b45bba022c11172b56','1a8ce7a0abffa846bac5805c4f91c648c800ba88']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=p26d7.13334cc344000b12"

   strings:
      $hex_string = { 8be55dc2040000d85332b02077684bb10ae3e79b91ecd3175f39d0aa52154593a55b292f03aa7b05278ce85a7c664e9b81447d05d5e6405356518bf051895424 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
