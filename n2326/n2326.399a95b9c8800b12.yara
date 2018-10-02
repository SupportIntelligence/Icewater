
rule n2326_399a95b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2326.399a95b9c8800b12"
     cluster="n2326.399a95b9c8800b12"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="macnist macos duvfuh"
     md5_hashes="['7b0741312f1268df16939ecfac938fdf42100cd7','ea9478b875bad11d4c2f76e1070bc3eb178e81bc','16fd7b0ee12d51fec5d66048349e65af69840736']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2326.399a95b9c8800b12"

   strings:
      $hex_string = { 2d0eca6a50b85e4f5c5199273f63e6c717458f11000c491d7c5f8860cd959ca37047e739b220f0ebc1bb5a6d4e528b46f56bad91caa934b5c89ae5ce6eab9375 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
