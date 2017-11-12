
rule n3e9_469633bdee620932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.469633bdee620932"
     cluster="n3e9.469633bdee620932"
     cluster_size="83"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virux advml"
     md5_hashes="['03f5fb3ea8fc2960ea0d43c0d163a2f4','0f62c2d37b7b86f9873634ff342bbc38','7302742c9c49a44a4fccc9172678bbeb']"

   strings:
      $hex_string = { 9dd9246b93e11d98dbfc26688fe61f6ea1ee2c4455d2342d2cb1323235513434342f463723294a30103f4f310b7f7b4507d397500ef2a95614fcb9612affb760 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
