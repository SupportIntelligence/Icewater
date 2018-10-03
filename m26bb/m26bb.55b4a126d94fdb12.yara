
rule m26bb_55b4a126d94fdb12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.55b4a126d94fdb12"
     cluster="m26bb.55b4a126d94fdb12"
     cluster_size="52"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug mikey malicious"
     md5_hashes="['f12b9574d82fb98d2208dcd6705778a71afba110','0d15f96925d09b0d7f68bf3325a8a7a52ac2f60e','abe78fa633a9294d3275a11e5f93a60929e62450']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.55b4a126d94fdb12"

   strings:
      $hex_string = { 33db4383c40c89be1c020000395de8764f807dee008d45ee74218a500184d2741a0fb6080fb6d2eb06804c0e1904413bca76f683c00280380075df8d461ab9fe }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
