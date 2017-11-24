
rule j2321_33132acbc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2321.33132acbc6220b32"
     cluster="j2321.33132acbc6220b32"
     cluster_size="12"
     filetype = "MS-DOS executable"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bdmj genpack flooder"
     md5_hashes="['02713fdea52f5ab35d131401c85c4376','1ee6b358d9c533291219cc1ddac44c58','f33d52ab6e060e3d686e56de57f91e6f']"

   strings:
      $hex_string = { 9fe8774a5470af2c4fe2e327f0f1db4ace31e5b23397a98af3a1b8503916be56c2fbca6415e9c95d32bb286e4661714e7621a4244b9382a0da65595949697e91 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
