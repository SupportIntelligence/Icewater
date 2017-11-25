
rule j3e7_7114d6e348000330
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e7.7114d6e348000330"
     cluster="j3e7.7114d6e348000330"
     cluster_size="489"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos risktool"
     md5_hashes="['003c550fb98472a27cf92d8af877f65f','008dbd9cca16ad9a1f87568d960ea114','067e6a9c24f50e4563accf43680a02e6']"

   strings:
      $hex_string = { 6e672f436c6173733b00135b4c6a6176612f6c616e672f4f626a6563743b000161001a616e64726f69642e6170702e4163746976697479546872656164002661 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
