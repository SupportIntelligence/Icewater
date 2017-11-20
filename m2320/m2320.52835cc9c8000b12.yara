
rule m2320_52835cc9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2320.52835cc9c8000b12"
     cluster="m2320.52835cc9c8000b12"
     cluster_size="101"
     filetype = "application/msword"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="obfuscated dldr jtvb"
     md5_hashes="['0544aca3171767bfdf5063a169686ee2','06d8a6d4945e4c7ae12384c4b0ef957c','2740fbcc7b2a47bf648b11e2cb210b41']"

   strings:
      $hex_string = { 3b6e5796831d288f247e923c6285d98bd7d41231cedafbf32ab8748e4e8cd6eb174c3cdd41db916db3a1edd8f9e6ab6a2bd5455d6ce2dfee030fff8a2d93f55b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
