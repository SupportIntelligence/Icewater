
rule k3f9_4b151a99fa230b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f9.4b151a99fa230b32"
     cluster="k3f9.4b151a99fa230b32"
     cluster_size="21"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="wabot emtaasmljwei shellini"
     md5_hashes="['1e425008f7608618209b85e5006863e8','3984c6c6dbab89cbdec6b449d0604042','d945068569380334fc7a4272f7d552bd']"

   strings:
      $hex_string = { b167fe95706f59850fe28b683de80db426d8eb0c929c46d9afc340b21a4441782c2072b0fade64536bf6dba1a6e606ca9702acc6995eef9d0eddf3f852e5cc91 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
