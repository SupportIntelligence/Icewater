
rule n3f1_291992b9c9800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f1.291992b9c9800b12"
     cluster="n3f1.291992b9c9800b12"
     cluster_size="217"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="slocker congur jisut"
     md5_hashes="['00287ed735bcc463c50c7eb042943281','0121cac907cd7950175ab9bf9f9afdba','11778581e4a8e1020550179d22b789bb']"

   strings:
      $hex_string = { 0757259699e34026471e054e087a5a6c24e185f7caa646521b779b239fba7bdbf012d91fcb013374a519c036a2b3a02d653d544bd2d89e242c0e7c92c6d18a6a }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
