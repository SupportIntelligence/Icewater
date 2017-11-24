
rule k3e9_6a92d79c16996d96
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6a92d79c16996d96"
     cluster="k3e9.6a92d79c16996d96"
     cluster_size="320"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="outbrowse bundler nsis"
     md5_hashes="['010caba65aa378aef43ccdcb4597971d','01ef7ddc4149015587870f796744ac20','155dcaf0b44fab88fd39ad69715f5bd5']"

   strings:
      $hex_string = { 615500de1ef25fa15efb070847bf83a00910d4d0b484338b4bf9ccee27f3fe523ce33f64b5fe7b568fff90d5f6ef59cf747f1bc365fc805192cc4ab797500e8c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
