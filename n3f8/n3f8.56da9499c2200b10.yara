
rule n3f8_56da9499c2200b10
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.56da9499c2200b10"
     cluster="n3f8.56da9499c2200b10"
     cluster_size="18"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="clicker androidos locker"
     md5_hashes="['823057d426f699b4b67ff1a4d9f887cd8de3b36f','1ecbb25ea5887b397c293d6144b3e20d0fe1d74e','a697f543a8ed583c2ac129fe11c596ddcb46de9c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.56da9499c2200b10"

   strings:
      $hex_string = { 6224313b00374c616e64726f69642f737570706f72742f76342f7769646765742f53656172636856696577436f6d706174486f6e6579636f6d6224323b00514c }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
