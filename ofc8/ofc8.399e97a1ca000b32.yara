
rule ofc8_399e97a1ca000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=ofc8.399e97a1ca000b32"
     cluster="ofc8.399e97a1ca000b32"
     cluster_size="101"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="riskware rogueurl gphji"
     md5_hashes="['f2d6544a02e960a9eda75bc915c926552e1b0c62','86541f6bfdef9bc5728b587764cbf728a25787a9','eadbd7b55b0c31eb1579e21d26d1b30e7d3d8d53']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=ofc8.399e97a1ca000b32"

   strings:
      $hex_string = { b105c85eb81230855486715b9c1d4ad5dad72880abad9160dd13b06a2ee3749a37451035f7c44e5064290c7b4dc5588a566e083f67dbac22ebe1613c2b2ae639 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
