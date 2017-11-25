
rule m3ec_5116c2ab17a30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ec.5116c2ab17a30b12"
     cluster="m3ec.5116c2ab17a30b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['00ef1c439ba54e1588af056e8c26d211','76c6d9a9d6a4b85e757062a3d997015e','d76281dde3cc9341a577d4c0c277a23a']"

   strings:
      $hex_string = { d63bc775105357ff35784f0201ff1528110001ebda8b4d1066893c4389195b5f5ec9c20c0033c0394424087e1433d2428bc8d3e2855424047509403b4424087c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
