
rule m3e9_091690399a9b0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.091690399a9b0932"
     cluster="m3e9.091690399a9b0932"
     cluster_size="7"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['2c61efdca2711bfe3f592576cbbcd6a8','542a2c8df5103f0c456ea4fb5b2e6156','fb540512e204548075af8b5e20c47a9b']"

   strings:
      $hex_string = { 97b90feb87188af07125884b2dad320ca86fe3742b949be58d6b90d80bd393ef516a8f84bd14dc821cbf64a0b10aa3949fe1a6b5651b6efd452461b091b4c1ee }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
