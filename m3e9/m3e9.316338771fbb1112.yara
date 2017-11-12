
rule m3e9_316338771fbb1112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.316338771fbb1112"
     cluster="m3e9.316338771fbb1112"
     cluster_size="30"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod wapomi"
     md5_hashes="['085a60a146a2d74f9ce439a9a2b26bb7','14ac59e6a92c78f80ba85c657f3c2e65','c0ccd42089cca2d714208a91416a21ba']"

   strings:
      $hex_string = { a3565d54009b481665ee9757d629864256138abe74ee50067d389ead9caa6115a5d3b0881614d0cb8a60a22948363b2b98bb32ef7131228e096c9e69dc6121c1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
