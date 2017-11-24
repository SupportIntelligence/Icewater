
rule o3e9_72dc3ec9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.72dc3ec9c4000b12"
     cluster="o3e9.72dc3ec9c4000b12"
     cluster_size="60"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock kazy nabucur"
     md5_hashes="['0063e61c25f2e2a6fee78e0aaa9a558c','1808ada8ea5a37d888853425cc019485','a3bd9a7a4cf4e1bc9d520d1397acb26c']"

   strings:
      $hex_string = { fd00f3f9f500cbe1d30094c8950076ad620081a273004bb6730082a47d0055413e001a14120059664f0054b9740013b565001bbd6c0015bd700043c48300dfd8 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
