
rule m2377_2b93130288056d16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.2b93130288056d16"
     cluster="m2377.2b93130288056d16"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker script clicker"
     md5_hashes="['4dcb46bd19e2d7712709e66e604a30ef','6e60b9b405d08069c9ac36166ba3d6a7','d524fd2b0f3042772f94198d3473a3f3']"

   strings:
      $hex_string = { 6e65772d6175746f6d6f746976652e626c6f6773706f742e64652f7365617263682f6c6162656c2f494d475f30393431273e494d475f303934313c2f613e0a3c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
