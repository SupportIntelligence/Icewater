
rule m3e9_039596d3c9a1a912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.039596d3c9a1a912"
     cluster="m3e9.039596d3c9a1a912"
     cluster_size="16"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="autorun ganelp fakefolder"
     md5_hashes="['098826c2fab2414062f17c642c6174d9','136c9e0fcc00b7f155c72bff6a5c7a22','dc068cf741ac9fb92d730757845c6610']"

   strings:
      $hex_string = { 3b443c503f593f000001007c00000054305d30a330af302b313a31273253327c329132d732e33288338f33aa34b134413548350436d6363d376f389138b338e4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
