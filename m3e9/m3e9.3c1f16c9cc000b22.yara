
rule m3e9_3c1f16c9cc000b22
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3c1f16c9cc000b22"
     cluster="m3e9.3c1f16c9cc000b22"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shodi prepender virut"
     md5_hashes="['356195e177135b1ba53dba18fda320c6','a296aab2f623fb36ed4399a78eabf26e','b9df67123293f72b31b6a8c48b8aec1a']"

   strings:
      $hex_string = { c07f068bc30bc774248b45f89952505753e8321a000083c13083f939895dbc8bd88bfa7e03034dd4880e4eebcc8d85affdffff2bc646f645fd028945f88975f4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
