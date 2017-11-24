
rule m2321_39991d8dc6220932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.39991d8dc6220932"
     cluster="m2321.39991d8dc6220932"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['362ff82d87c046aaf1beeb85105f94dc','43856528a9b1d4a1f5122f84dcb9638c','f547084401e32ea8e3f65d2220686beb']"

   strings:
      $hex_string = { 94de7114db11051be65644762075e253434e90e9c8e8f1b77e13c7dfc11e5e77f2c423fbf34eace5383bb919c91d9f7f2785f474216b737a39d92b348ecd37b8 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
