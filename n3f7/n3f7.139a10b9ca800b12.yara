
rule n3f7_139a10b9ca800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f7.139a10b9ca800b12"
     cluster="n3f7.139a10b9ca800b12"
     cluster_size="3"
     filetype = "text/plain"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery classic epkubn"
     md5_hashes="['944daa3821c7e4053b47884caef0196e','b037ba48bd1a08f43443ba3443ba6a72','bdd44b3d30cc3fb62693222a7ca8c795']"

   strings:
      $hex_string = { 305d292c617d2c50534555444f3a66756e6374696f6e2861297b76617220622c633d21615b365d2626615b325d3b72657475726e20572e4348494c442e746573 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
