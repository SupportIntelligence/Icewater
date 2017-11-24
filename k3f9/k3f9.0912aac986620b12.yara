
rule k3f9_0912aac986620b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f9.0912aac986620b12"
     cluster="k3f9.0912aac986620b12"
     cluster_size="11"
     filetype = "MS-DOS executable"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="brontok email pazetus"
     md5_hashes="['01098b9828b95dc9ca2b5fb0bd0d49d7','02f9cdb0fb6a0251c9773d6620fc8732','b31635e3497c99b592423884a99896ba']"

   strings:
      $hex_string = { 52973ee6a0378db4d3e730d7e51d047ffe24c470c0e41606f2d0ac60958e2ed449fb5acead9f9b63d2c85bc77ce10b91545e710ac588582cb82764478c85ec31 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
