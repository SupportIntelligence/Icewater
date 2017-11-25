
rule m3e9_134e5cc9cc000916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.134e5cc9cc000916"
     cluster="m3e9.134e5cc9cc000916"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore malicious unwanted"
     md5_hashes="['19b2c2c1c9dc12536de19d34c99b5e90','2a9dc374cd49b32b628db54546ae2581','eecdcb5b2a786b6443d79d0ccb020138']"

   strings:
      $hex_string = { a58109fcac77167237ae23e80f3a2713f4425830558c7604f6063cd08d5f6e86ba2e1824ad5dc7b7fd8e9dbdefa8d7a475d6bb3b4005e4340b25d17be3d30219 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
