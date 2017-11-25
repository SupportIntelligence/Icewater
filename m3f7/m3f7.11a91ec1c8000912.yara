
rule m3f7_11a91ec1c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.11a91ec1c8000912"
     cluster="m3f7.11a91ec1c8000912"
     cluster_size="13"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script html redirector"
     md5_hashes="['188cbb76274802f82f86f0e0d3cadf1d','20667625a5a4ab595a66ae832738ea1e','db7f50803f5031fa1b056f61cffffa26']"

   strings:
      $hex_string = { 415649346f7935625a474a695575676362667248367557564d7144536652783552476e516e786136702b774b784e7075316e592f3973754f525a454e64376559 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
