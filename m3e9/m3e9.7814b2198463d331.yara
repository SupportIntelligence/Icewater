
rule m3e9_7814b2198463d331
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.7814b2198463d331"
     cluster="m3e9.7814b2198463d331"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="sirefef vobfus diple"
     md5_hashes="['1421c9aa240acb8cccda76fe6c5768b8','49fdd4d0bef6b7a034379000b9173564','f9cf3733fa743bc71561bf9ba2f8ca52']"

   strings:
      $hex_string = { 35601140008bc8ffd6898570ffffff8d45d0506a01ff15781140008bc8ffd6668bc88945e8663b8d70ffffff0f8f980000008b1757ff9204030000508d45c850 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
