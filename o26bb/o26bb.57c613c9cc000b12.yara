
rule o26bb_57c613c9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.57c613c9cc000b12"
     cluster="o26bb.57c613c9cc000b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="gamehack malicious riskware"
     md5_hashes="['b6c5bfefe743e2bbbd7a521b57731ad07910a620','60cc151715bf9c3fb9d900ad8055cf3d3ba6fa89','5fecaa8ca53362f7f8e58e75298c6a5e2cf51a00']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.57c613c9cc000b12"

   strings:
      $hex_string = { 44ba699380c21928431806839529860442dc11c070130d55775da73e419a7ebd98259e5330b1221f65e4e56d2cae6292f472ac904f01978dd558b85ad166f0c1 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
