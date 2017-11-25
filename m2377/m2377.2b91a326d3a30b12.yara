
rule m2377_2b91a326d3a30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.2b91a326d3a30b12"
     cluster="m2377.2b91a326d3a30b12"
     cluster_size="6"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['6225136277248fc7f6a29b5d5898432e','78849b23e811fa0fccd908007487aedc','dbd07b978b9579305759b477f30a787c']"

   strings:
      $hex_string = { 414141564e492f70672d69484962447673592f7337322d632f436962656c6c655f4d616e63696e6e695f30322e4a5047272077696474683d273732272f3e0a3c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
