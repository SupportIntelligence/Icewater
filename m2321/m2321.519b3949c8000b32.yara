
rule m2321_519b3949c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.519b3949c8000b32"
     cluster="m2321.519b3949c8000b32"
     cluster_size="18"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['0a967f315f550455b76b838f3433be43','0e564483f151f0488910dffb482acf83','e45ad3515e7e54c53e43dd3d1003b284']"

   strings:
      $hex_string = { 9a9c74197b93a2d38fab3d79f1ce27b2040152992af9f39e5f18debc6aad24351216b0f478924517c75bc3815abd29963055103e41697ca40339335cc282a62d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
