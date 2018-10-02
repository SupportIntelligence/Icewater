
rule o26bb_3139cca9d9a30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.3139cca9d9a30b12"
     cluster="o26bb.3139cca9d9a30b12"
     cluster_size="26"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy adload malicious"
     md5_hashes="['e42d93855a71257f3cb7394eb0bff0d29b49463a','5d66770fae908539512367daf34540edc80de865','1b4b40f4720535e105bae4138e9e13ddd0ca8ec9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.3139cca9d9a30b12"

   strings:
      $hex_string = { 4efd0fb642fd2bc8741233c085c90f9fc08d0c45ffffffffeb0233c985c90f85a1f7ffff668b46fe663b42fe0f8491f7ffffe9450400008b46e13b42e10f8482 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
