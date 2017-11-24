
rule p3f7_691c9499c2200b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p3f7.691c9499c2200b16"
     cluster="p3f7.691c9499c2200b16"
     cluster_size="4"
     filetype = "ASCII text"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos shedun triada"
     md5_hashes="['0be4366982008d5fc27249bd8da17d6a','0ca9d9920cc28a2bf9de2e6b20d63079','3afdb7fae7910daebe23424c7c1d855b']"

   strings:
      $hex_string = { 1099c1b5a450b8516e38be84effb835dd1f94f753fcca3707f087b19ec984e904b96b0f793af9730d985dc591b2deac52431430e76925bb20bf236a677ab237e }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
