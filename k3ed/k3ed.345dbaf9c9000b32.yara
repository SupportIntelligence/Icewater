
rule k3ed_345dbaf9c9000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ed.345dbaf9c9000b32"
     cluster="k3ed.345dbaf9c9000b32"
     cluster_size="10"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="lapka networkworm amanjxeb"
     md5_hashes="['a7990fbcb25eacbf00667d7d80a261a3','b634d49a11287913d6f9abbc5af6794d','f1e57bbb0ebf806329d417d31fb8835f']"

   strings:
      $hex_string = { 4c3471347c349234ae34b43405351535373547355e356435733578358635d935df35f6350d3656366d36753684369136ac36d036f93622373137483750375837 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
