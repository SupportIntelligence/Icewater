
rule k3ed_6b1b97a1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ed.6b1b97a1c2000b32"
     cluster="k3ed.6b1b97a1c2000b32"
     cluster_size="178"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gamarue akhj bundpil"
     md5_hashes="['00649f52b9cc0539f35a13836faae8aa','0109c19a869be113eabf06f2020d7818','14195cbf55efaea6100cf0cc4bccd6aa']"

   strings:
      $hex_string = { db1656a05294fc5a4c1c6801235eebc4cae8b008268302205d287c4f301257a9872ed506440b9137fefb404f4baec382ef6a50ddd8291a6890d164cd49a32f04 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
