
rule n3e9_1b1c9ec9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1b1c9ec9c4000b32"
     cluster="n3e9.1b1c9ec9c4000b32"
     cluster_size="142"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qvod jadtre viking"
     md5_hashes="['07b62737293b0cccd50e31b98c2185ba','0beee95db54f0432c330704d9b1a4018','7e48f8e222c9187f4d680e0168df9b59']"

   strings:
      $hex_string = { a399d03f7586835490d74e58dd8fe44f7b533c7826042f29b6bc550b526bcdc376d91941b91065c9ad3a5dedae71000e36244d0ad21345700ddfef674ca0afb2 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
