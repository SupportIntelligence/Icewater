
rule m2321_493cd52adcbb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.493cd52adcbb0932"
     cluster="m2321.493cd52adcbb0932"
     cluster_size="27"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tovkater aiwe aebe"
     md5_hashes="['0b58cd037464a187f06dbce4f202bc88','189f88d2dc0d2ab28139260433455b4c','9f53de1487c04e7023dbacbc73fd86a5']"

   strings:
      $hex_string = { a3f1ca07db616549c7435ab925233e0d5cc9a8f9a460143324c57453a942d23276c04c486e380a19211cd4fd94e38b8c411d36cd3d343befb3cbe9cced44a15b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
