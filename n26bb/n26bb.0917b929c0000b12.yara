
rule n26bb_0917b929c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.0917b929c0000b12"
     cluster="n26bb.0917b929c0000b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="krypt loadmoney cryptor"
     md5_hashes="['ab84172c1c277ae086d4b13ffe9671573f23c2e7','11217820635930b4fa9589037aa562f5a38946a6','28513bc8d4484617146c0599fce3cbe6f3e67345']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.0917b929c0000b12"

   strings:
      $hex_string = { c04a611df12f0efabe79f7a523ef55519684cddbe3b96e3e31d80a2067c7f4d9bf94eb47043e02ce2aa25d870409f6309d188a97b2aa1cfc41d2a136cbfb3d91 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
