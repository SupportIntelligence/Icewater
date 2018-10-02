
rule k2319_392c96b9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.392c96b9c8800932"
     cluster="k2319.392c96b9c8800932"
     cluster_size="21"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['03836f7c40beef21618816c0392375048baf48dc','48b700a4c05f623e5a793338aaa2d394920012b7','358b1ed89977af08d5ffe9b75df3cafb0045210f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.392c96b9c8800932"

   strings:
      $hex_string = { 775b575d213d3d756e646566696e6564297b72657475726e20775b575d3b7d766172204f3d28307844413c2835322e2c37342e394531293f283134382e323045 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
