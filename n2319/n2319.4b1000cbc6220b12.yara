
rule n2319_4b1000cbc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.4b1000cbc6220b12"
     cluster="n2319.4b1000cbc6220b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe blacole blacoleref"
     md5_hashes="['3bd3c0c965795d94310d390bfcdd3a976aa6402b','c01bfdad7aef43bd7452c3ad58c56af5d2affb43','919b22bb65df33ecf69c8eeee4594a47934ac557']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.4b1000cbc6220b12"

   strings:
      $hex_string = { 4a4f626a6563743a3a736574282470726f70657274792c202476616c7565203d204e554c4c2920696e203c623e2f686f6d652f6a77777761616e632f7075626c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
