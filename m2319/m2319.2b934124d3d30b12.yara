
rule m2319_2b934124d3d30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2b934124d3d30b12"
     cluster="m2319.2b934124d3d30b12"
     cluster_size="7"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['02f2a35c93afd330066038ee177abf39','06c5cf998377624836bd10bdfaa2d863','f9430f0abdcd4be066339ee2713c4fa6']"

   strings:
      $hex_string = { 312f762d6373732f3336383935343431352d6c69676874626f785f62756e646c652e637373277d2c2027646973706c61794d6f646546756c6c2729293b0a5f57 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
