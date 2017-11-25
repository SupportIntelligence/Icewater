
rule k3f7_19931cc1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.19931cc1c8000b12"
     cluster="k3f7.19931cc1c8000b12"
     cluster_size="41"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="html refresh redirme"
     md5_hashes="['063895ca8fc362f48d9f44951bb48ef0','0a180512d97b3a70e6d69f185d2b8670','71a64fbdd0cb17382ce22cfe27d66922']"

   strings:
      $hex_string = { 3737752f496942705a443069567a564e4d4531775132566f61556836636d5654656b355559337072597a6c6b496a382b494478344f6e68746347316c64474567 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
