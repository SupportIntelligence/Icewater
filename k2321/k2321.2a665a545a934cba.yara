
rule k2321_2a665a545a934cba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2a665a545a934cba"
     cluster="k2321.2a665a545a934cba"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy flmp"
     md5_hashes="['14452531b78e81aac6feba1ffff8624f','22b1f5014e39d6f91f729e6b9fcc48b8','948e1856062a605534936afa624c5366']"

   strings:
      $hex_string = { c6844bdd78b1eaf43c883a16a2c263d10249e648e220c5407e3f00ae0a68f69b99e505387d4a98e808a86f42b255e9c1a726037c334165533bc0be4caa89c9a3 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
