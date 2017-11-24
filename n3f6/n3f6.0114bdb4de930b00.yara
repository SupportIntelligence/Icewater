
rule n3f6_0114bdb4de930b00
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f6.0114bdb4de930b00"
     cluster="n3f6.0114bdb4de930b00"
     cluster_size="139"
     filetype = "application/x-iso9660-image"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="genieo bundlore geonei"
     md5_hashes="['0157f95ec1a8680880f2bc7bd883e769','029a19ed3e123e88c1aa42ce251a1511','1c93bb07c9499deac6050e1abe16a488']"

   strings:
      $hex_string = { 04a16915486d1e630ad10b912bc86e89eb132d83a832002100e203945144caa6992a61a597a06454fb2c9c3cc15047054bd68f5dd456145d8a34b0c916910710 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
