
rule k2321_2937842addb39912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2937842addb39912"
     cluster="k2321.2937842addb39912"
     cluster_size="8"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installm unwanted downware"
     md5_hashes="['0aca4c4c92f717be7e09682e87162b5c','3f145c1b08aac378414d3c5019b41690','d9f4320f59247899fee23a94c237d55b']"

   strings:
      $hex_string = { bf8f4046cb3d2060caf76b4f0fd1288d05a803bd86422b6ae7c6f4a1fa0c9d7122022d82eb0153a879ecadb14c3067f8de7b5b75ea80485954b02699f9431d4d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
