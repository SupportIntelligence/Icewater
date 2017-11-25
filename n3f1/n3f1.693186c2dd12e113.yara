
rule n3f1_693186c2dd12e113
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f1.693186c2dd12e113"
     cluster="n3f1.693186c2dd12e113"
     cluster_size="5"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="flystudio wpepro hacktool"
     md5_hashes="['080ed46d827aae43655930ad19722120','311fedad7ac797efbc95e69493f45c58','ec0bec43e6dabae0deab0d5634fba87c']"

   strings:
      $hex_string = { 4c930534ee767ca27139a16bd020fb27a3811de9319c95f0d62aa8ebc82386c9972edafcdec69d88ab59801e335d1f6c11194e4955e83653e666d794b6353afa }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
