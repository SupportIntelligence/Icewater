
rule k3e9_7ab24290cdbf0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.7ab24290cdbf0912"
     cluster="k3e9.7ab24290cdbf0912"
     cluster_size="8177"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nsis malicious adload"
     md5_hashes="['00014a8795ae6f9af8c199259052118d','00155f4ea8fbc066f14ced4d2bbc2e64','00840180119b9649bd0740626d6ddc18']"

   strings:
      $hex_string = { b008481e47a950ab5d4d2cda32bf58fe850c6c9acc43d859fb9b01f64f2b309233ddde9fc06906709c68ce638e0a5bf7c49e9da862df132f003aa17e0222ad7c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
