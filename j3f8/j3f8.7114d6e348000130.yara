
rule j3f8_7114d6e348000130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.7114d6e348000130"
     cluster="j3f8.7114d6e348000130"
     cluster_size="227"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos piom"
     md5_hashes="['000996281d0a90e901a3fec13ec438d0','00b3c6dad352812a83b51f88ee9b8b0f','16c4c2d858a35f4e9f6b12b1f46d6902']"

   strings:
      $hex_string = { 6e672f436c6173733b00135b4c6a6176612f6c616e672f4f626a6563743b000161001a616e64726f69642e6170702e4163746976697479546872656164002661 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
