
rule m3e9_7814b21984635311
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.7814b21984635311"
     cluster="m3e9.7814b21984635311"
     cluster_size="14"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus diple sirefef"
     md5_hashes="['2c54da1413c55ac4ca720005e9f44c6c','3fefe875f6038a1d0a751d754562838f','e06e3adebf2c79509a2b945bebef2b07']"

   strings:
      $hex_string = { 35601140008bc8ffd6898570ffffff8d45d0506a01ff15781140008bc8ffd6668bc88945e8663b8d70ffffff0f8f980000008b1757ff9204030000508d45c850 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
