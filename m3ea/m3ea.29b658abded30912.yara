
rule m3ea_29b658abded30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ea.29b658abded30912"
     cluster="m3ea.29b658abded30912"
     cluster_size="10"
     filetype = "application/java-archive"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="generickd androidos hiddad"
     md5_hashes="['06f4ab66e6e9853d07f2e6fa93ab5f02','164861015d1aec7ee7ba23aec586829e','f610e09673fd68208b018c738e2708e3']"

   strings:
      $hex_string = { b916236f4d7145e8f85a609967ab77dd43d3531933805e9c7297d624374a5ff7dc0edbaac0c6a789641d965b7ed51a26e136d7a22531927841e2f6c70af0fdb1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
