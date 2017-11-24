
rule m2319_358b7849c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.358b7849c8000b32"
     cluster="m2319.358b7849c8000b32"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script trojandownloader"
     md5_hashes="['328aa8bf844d46487b9bd1c7109ed63f','6ef3714e8ee662f190ece00c8c2fe8ad','b72e3b261ec8c272edaf1f20a5adc0fa']"

   strings:
      $hex_string = { 2428276963657461627334323227293b200a09766172206f626a656374203d206e6577204c6f66536c69646573686f7728205f6c6f666d61696e2e676574456c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
