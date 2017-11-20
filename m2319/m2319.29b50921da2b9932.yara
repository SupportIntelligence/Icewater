
rule m2319_29b50921da2b9932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.29b50921da2b9932"
     cluster="m2319.29b50921da2b9932"
     cluster_size="4"
     filetype = "text/plain"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script classic"
     md5_hashes="['1182fe7a0d2bbeda8f8c8fcb996d7694','7a5a4a1459667145be41258c9dab9f8e','a117dbe5f80de627a3d47df4a5afec60']"

   strings:
      $hex_string = { 305d292c617d2c50534555444f3a66756e6374696f6e2861297b76617220622c633d21615b365d2626615b325d3b72657475726e20572e4348494c442e746573 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
