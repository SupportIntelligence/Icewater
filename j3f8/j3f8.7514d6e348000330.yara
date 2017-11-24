
rule j3f8_7514d6e348000330
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.7514d6e348000330"
     cluster="j3f8.7514d6e348000330"
     cluster_size="76"
     filetype = "Dalvik dex file version 035"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos piom"
     md5_hashes="['00be090f1e6fea4f5ceffc3c6ffc76bc','0c6268aee808568c058a2430e599957f','42966288d372d8b68547279150ef6321']"

   strings:
      $hex_string = { 616e672f436c6173733b00135b4c6a6176612f6c616e672f4f626a6563743b000161001a616e64726f69642e6170702e41637469766974795468726561640026 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
