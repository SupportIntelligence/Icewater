
rule m3ed_31fa528d86220912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.31fa528d86220912"
     cluster="m3ed.31fa528d86220912"
     cluster_size="44"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul akyn"
     md5_hashes="['00d865173a1b05c569298b43e1ea809b','15b039f4d627576a55aff73a8b24d0f7','b48ec822f346558b0dfd808864293f92']"

   strings:
      $hex_string = { f47cd08bf06a02c1e6028d4de85a2bce3bd07c088b31897495e0eb05836495e0004a83e90485d27de733c05e6a1f592b0d8cdb0010d3e38b4decf7d91bc981e1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
