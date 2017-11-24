
rule m3e9_091e904bc6620b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.091e904bc6620b32"
     cluster="m3e9.091e904bc6620b32"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar shyape virtob"
     md5_hashes="['0ce4eb9064d49a1b762f64d6b8aecf97','3fa147d2f2412b7174c91414667ca524','da60f82d6a71b7f37f4feb75ced8f798']"

   strings:
      $hex_string = { 97b90feb87188af07125884b2dad320ca86fe3742b949be58d6b90d80bd393ef516a8f84bd14dc821cbf64a0b10aa3949fe1a6b5651b6efd452461b091b4c1ee }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
