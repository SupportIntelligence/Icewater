
rule j2319_139c1bb9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.139c1bb9c8800b12"
     cluster="j2319.139c1bb9c8800b12"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="redirector fakejquery html"
     md5_hashes="['91d6d7b472add16e4cf645e6076535b2','ca38d0507800559e4515c7a051abe149','d2f5656449022351d80bbd7e6884ae08']"

   strings:
      $hex_string = { 616b6f7a69636b692e7a612e706c2f6a732f6a71756572792e6d696e2e7068703f635f7574743d47393138323526635f75746d3d272b656e636f646555524943 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
