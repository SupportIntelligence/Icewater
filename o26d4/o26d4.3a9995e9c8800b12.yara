
rule o26d4_3a9995e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d4.3a9995e9c8800b12"
     cluster="o26d4.3a9995e9c8800b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious neoreklami"
     md5_hashes="['9ee4f000bf12c56b93549e1a92f4a218d24bd29f','d31e9fb307b0b7c8855fa2ba8f5337f1a9a4926e','8a5594d40efd384abc5f1affaf65e6e3b69c14ab']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d4.3a9995e9c8800b12"

   strings:
      $hex_string = { 0033c9538b5d0c2bd843d1eb3b450c568b75100f47d985db74238bf80fb70750ffd28b55f48d7f0266890683c6028b45fc408945fc593bc375e28b7df089375e }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
