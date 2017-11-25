
rule j3e7_725f2da9c0000b10
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e7.725f2da9c0000b10"
     cluster="j3e7.725f2da9c0000b10"
     cluster_size="3578"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos skymobi"
     md5_hashes="['0000eb8544bc6928d8b9e415d5fd8567','000999a4fcbce5f6df480e3930e468b5','01cab85d0f9754e1768b046f273785c3']"

   strings:
      $hex_string = { 5a79a53c401a008301020000071d782d5a4b3da2411f0066020000070e8c1a2000bb0103000000070e01290f01130f9696a501180f784b2e1c000600070e000b }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
