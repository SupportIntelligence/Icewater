
rule n3fa_119992b9c8810b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3fa.119992b9c8810b12"
     cluster="n3fa.119992b9c8810b12"
     cluster_size="14"
     filetype = "PE32+ executable (DLL) (GUI) x86-64"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="kryptik fari malicious"
     md5_hashes="['04910d8b10e5bed15a2d89fab283d9fd','2020f2b46a6ddb5edbf90ee511b3e8cc','e669c42bfe39ceaa53f86d3902d36aa0']"

   strings:
      $hex_string = { d633126490232da8e8fd1d50d8aa1cc9ec62fc9aa57fc4fb45aca0d0191b61d3cb66a70b2e2acef27b938e99e31eb521e62b0109420fdbcc5822f35d5a60344f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
