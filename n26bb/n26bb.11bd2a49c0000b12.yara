
rule n26bb_11bd2a49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.11bd2a49c0000b12"
     cluster="n26bb.11bd2a49c0000b12"
     cluster_size="68"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dorifel bafl attribute"
     md5_hashes="['6ed91b10ecc2ec3e444147ef3cd5cdf610d53bbc','6b3cbc7b37d2c3baaf6436298413fc16ba1eb5a5','02db92a3e5be0d5607a9038d0775fd4ab1d2524a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.11bd2a49c0000b12"

   strings:
      $hex_string = { 85c074f68a44d0045dc204006a0cb872184300e8e14601008bf18975ec8326008365fc008b450833c96a085af7e20f90c1f7d90bc851e83491ffff598906eb11 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
