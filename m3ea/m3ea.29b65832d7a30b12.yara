
rule m3ea_29b65832d7a30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ea.29b65832d7a30b12"
     cluster="m3ea.29b65832d7a30b12"
     cluster_size="9"
     filetype = "application/java-archive"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos generickd hiddad"
     md5_hashes="['2310a784647b4bdd4c8a7942fef37e49','2761019ada67ad67af09a88480dd7211','e40e388284bb1ab3c32dca35afcc52d4']"

   strings:
      $hex_string = { b916236f4d7145e8f85a609967ab77dd43d3531933805e9c7297d624374a5ff7dc0edbaac0c6a789641d965b7ed51a26e136d7a22531927841e2f6c70af0fdb1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
