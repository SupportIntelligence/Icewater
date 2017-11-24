
rule k2321_2b14ad699c9b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2b14ad699c9b0b12"
     cluster="k2321.2b14ad699c9b0b12"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba vbkrypt emotet"
     md5_hashes="['848aa7b04d552e74bcb971791ff7d755','9e28dbf2879c9811e51042b2f62d134a','ef180219d6178d52101e5a1ea09e3fc3']"

   strings:
      $hex_string = { 03dc3008b40a17e6b39d05213a85ed22089f1e60adc57d96b13682f04d3d6b2b7e339cb5133d38c0da0b42471fd641fc26897514842f5d5927d183ee18ca04a3 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
