
rule k26c0_13b14cb8c2a00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26c0.13b14cb8c2a00b12"
     cluster="k26c0.13b14cb8c2a00b12"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="ursu malicious clipspy"
     md5_hashes="['bb72706591f076a53ddbf90f7f736b6093da811c','f4136154abf82770aa6541a466bd4da5a20bedc9','edd16d2c18ae8fde9488f992e275b5dd18af6312']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26c0.13b14cb8c2a00b12"

   strings:
      $hex_string = { 7a655f636f737400071401a509000015697838365f74756e655f696e64696365730004f8000000076b015a140000115838365f54554e455f5343484544554c45 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
