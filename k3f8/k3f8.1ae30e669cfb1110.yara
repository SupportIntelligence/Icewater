
rule k3f8_1ae30e669cfb1110
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f8.1ae30e669cfb1110"
     cluster="k3f8.1ae30e669cfb1110"
     cluster_size="579"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smforw androidos smsspy"
     md5_hashes="['1b0d1ac1614a8b826c22d9e0e64f45434f84dbc4','33969b8abac268bb9c2cec27f8f5a63fc9212121','9db3cf17d439fa4804ea0e20a98f3f6134a142f3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k3f8.1ae30e669cfb1110"

   strings:
      $hex_string = { 0f0100000b06160c0000310c060c3a0c1600bb6128e522082f0070104b00080054ec1600120d7040d900ced86e104e0008000c04214a81aabb1a100a0d0328fe }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
