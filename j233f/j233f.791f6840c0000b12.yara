
rule j233f_791f6840c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j233f.791f6840c0000b12"
     cluster="j233f.791f6840c0000b12"
     cluster_size="15"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="voiv script expkit"
     md5_hashes="['74444cd1897873229425bfc91d246280330d21f5','0016b378964ae2b53642c22baca972ba97944974','25afcb99c526a4660ff62869fdbdd19dd1540138']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j233f.791f6840c0000b12"

   strings:
      $hex_string = { 002e0030002200200065006e0063006f00640069006e0067003d0022005500540046002d003100360022003f003e000d000a003c005400610073006b00200076 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
