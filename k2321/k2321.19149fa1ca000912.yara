
rule k2321_19149fa1ca000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.19149fa1ca000912"
     cluster="k2321.19149fa1ca000912"
     cluster_size="25"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre small"
     md5_hashes="['0013c88df9ed46ae9fe9bda89b614f64','0a3c29d21fbd8de9ac2ca071943e9133','a425560b67046bd0d7d0902fc3d71630']"

   strings:
      $hex_string = { 4bb5cbeb5ea1b2ca6cd6c1f3493a561b0399d22788c636fcd95aabb3f54467772a241c62e765c3f414116d5b2515395dd9348df0d5bd661d35fe4637f2a8cfde }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
