
rule o3e9_2752d1b9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.2752d1b9c2200b12"
     cluster="o3e9.2752d1b9c2200b12"
     cluster_size="49"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious adwaresig toolbar"
     md5_hashes="['037c1b0ea77d09797ac2fee97f86844c','0b4d558b9b62e6e9f257291515685642','679cce3a9e4425e64ebc559f061f7ac2']"

   strings:
      $hex_string = { 117d07eb0ff339e5edb6ef587f99c56ddeb0ff00338adbbd61fe6715b77ac3fcce2b687b9314d6d7105c2fad6f750bc1710f2e3ca29519245e5fb3c95b2c84a5 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
