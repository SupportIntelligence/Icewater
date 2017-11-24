
rule k3e9_29259162d9eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.29259162d9eb1912"
     cluster="k3e9.29259162d9eb1912"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus symmi vbkrypt"
     md5_hashes="['09fde53de17f2b44132b0a77f8402367','4d224d00ba39c11d7cbacf8d113a3218','a482038ef3b3aa4dc156df50dc2221a8']"

   strings:
      $hex_string = { a223ab6f52b25b27ca5495e268d855dff39233fb7ce74b5aa7a01aeda19e01c3203bafdca32873d17b4e3230dd22171b96ec62439ab6bd00820cc24d10460b34 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
