
rule m3e9_693f85ac9b9f4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.693f85ac9b9f4912"
     cluster="m3e9.693f85ac9b9f4912"
     cluster_size="9"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qvod viking virut"
     md5_hashes="['039bf21377bb7b1827bbbe739322ec38','5ae9a6aae71d9901432e5247e4922fa7','fabf4a7fe5f5ea0086a34d68cfa0383d']"

   strings:
      $hex_string = { 654c864752cba5bf38519004fb1816a88fc2a288823baf1a45b908570e9104be55dde19cd59dd6223231d95c1425eeac107f5f8435547a0b9311ab6abad26bbc }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
