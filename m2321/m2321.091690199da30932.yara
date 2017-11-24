
rule m2321_091690199da30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.091690199da30932"
     cluster="m2321.091690199da30932"
     cluster_size="8"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar shyape virtob"
     md5_hashes="['12c870f828d0703d43bc56f69de19980','2b57c21bb67fd8002e530a5d8a6c4192','ee625bd40e048a66b80dad3248b13ee0']"

   strings:
      $hex_string = { 97b90feb87188af07125884b2dad320ca86fe3742b949be58d6b90d80bd393ef516a8f84bd14dc821cbf64a0b10aa3949fe1a6b5651b6efd452461b091b4c1ee }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
