
rule m3e9_693c244dd1a31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.693c244dd1a31912"
     cluster="m3e9.693c244dd1a31912"
     cluster_size="14"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus symmi vbobfus"
     md5_hashes="['233eebc529013b171cfad0f3765b7850','42ce307136805c13a610ec5679f3d8ad','ee95c55beb02464627e0a8de77f35866']"

   strings:
      $hex_string = { 150a0e13151e50515c5c5d688b8e8d8a7c69969795b5c6a0bb9fc3ccd9f8fffffffffaf9f1ad000000f2ffff65151f1e0f10121e22575c5d7a7d80a6abc8c8bb }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
