
rule k2321_19149fa1ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.19149fa1ca000b12"
     cluster="k2321.19149fa1ca000b12"
     cluster_size="32"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre small"
     md5_hashes="['0176d68af4c775452bcf38943c7c8fad','09c716d198a85513bd2de8283cdce552','aab6216221f1213d0a7fe11549523725']"

   strings:
      $hex_string = { 4bb5cbeb5ea1b2ca6cd6c1f3493a561b0399d22788c636fcd95aabb3f54467772a241c62e765c3f414116d5b2515395dd9348df0d5bd661d35fe4637f2a8cfde }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
