
rule m2319_439891e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.439891e9c8800b12"
     cluster="m2319.439891e9c8800b12"
     cluster_size="7"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script faceliker trojanclicker"
     md5_hashes="['299a63634847dbb758c2a427b637afd7','543ce475da47239ce34ee53487b9179f','f4ca35360cd8cd51792bfb7c24a33473']"

   strings:
      $hex_string = { 61707065725c275d22292e6869646528293b7d66756e6374696f6e20436c69636b4a61636b466253686f7728297b6a517565727928226469765b69645e3d5c27 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
