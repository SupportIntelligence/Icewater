
rule k2319_4694ea3bd8bb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.4694ea3bd8bb0b12"
     cluster="k2319.4694ea3bd8bb0b12"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script browser"
     md5_hashes="['b86059ffc4f87ffc67cc12617961241c35416021','af02cad16816d4e0bc1e061a78b60ff777dce74d','3ee28eff695353e9b76c6513db0bf87835daa25f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.4694ea3bd8bb0b12"

   strings:
      $hex_string = { 2e3333364533292929627265616b7d3b766172205a376e38563d7b27433331273a342c27553231273a227061222c276f3756273a66756e6374696f6e28472c78 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
