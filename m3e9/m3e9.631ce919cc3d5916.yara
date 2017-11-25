
rule m3e9_631ce919cc3d5916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.631ce919cc3d5916"
     cluster="m3e9.631ce919cc3d5916"
     cluster_size="15"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['191093369df425c7d197ef6fdab985ff','252c71083326b7d54f4a41fc367e7a55','fa0369c6728106f22a909189d40bff4c']"

   strings:
      $hex_string = { 03f3aa33ff3be774c5397df87e368b4dfc8bc7992bc2d1f88d34088b45f40fb7047850e8d8fcffff8bcf83e101c1e1028bd16a04592bcad2e00806473b7df87c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
