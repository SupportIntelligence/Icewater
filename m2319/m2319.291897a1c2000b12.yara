
rule m2319_291897a1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.291897a1c2000b12"
     cluster="m2319.291897a1c2000b12"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe blacole blacoleref"
     md5_hashes="['75b95dead5d83e44d3e82010b97659d4b4430de2','dc34376e78304f02946ad5776f944f974f9d085c','ef944b8618931c25114dc8f3df38d2e6ab488038']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.291897a1c2000b12"

   strings:
      $hex_string = { 4a4f626a6563743a3a736574282470726f70657274792c202476616c7565203d204e554c4c2920696e203c623e2f686f6d652f6a77777761616e632f7075626c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
