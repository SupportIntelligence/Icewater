
rule m2377_63b9a808d9bb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.63b9a808d9bb0912"
     cluster="m2377.63b9a808d9bb0912"
     cluster_size="14"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['06d83a1f9860dc0179bdd22278df9f6c','1c171c6aeb6e91fa2fbe985e73956a4e','e94415c57daad9d916ea8867354ffe69']"

   strings:
      $hex_string = { 626a2e57726974652043687228434c6e6728222648222026204d6964285772697465446174612c692c322929290d0a4e6578740d0a46696c654f626a2e436c6f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
