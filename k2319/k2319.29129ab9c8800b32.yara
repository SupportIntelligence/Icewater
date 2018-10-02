
rule k2319_29129ab9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.29129ab9c8800b32"
     cluster="k2319.29129ab9c8800b32"
     cluster_size="23"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['b8c4828f0ec470727722e8dac39d1e24a5daff14','1f7630c22427f9c9594c07f2aba2f1bbb5b11d21','012123499178b501bf304692576c606df05909ff']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.29129ab9c8800b32"

   strings:
      $hex_string = { 3245323f38333a28307845312c3078313730292929627265616b7d3b666f72287661722059385220696e206d33563852297b6966285938522e6c656e6774683d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
