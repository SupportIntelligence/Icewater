
rule m3e9_291d4ab8b0a59ac7
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.291d4ab8b0a59ac7"
     cluster="m3e9.291d4ab8b0a59ac7"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal vjadtre wapomi"
     md5_hashes="['0a28eee65aa421a3a2f78b5010020aae','35b85881ed6c74f48bab705e000d7d54','bbb45a8d693a54624e3c62d9cb2a2a86']"

   strings:
      $hex_string = { d44e7e1411a1ad49c6ff2954124fef9151a7bed2081c8f4b35617a01c886d0f09ef288f9c0418ce128eec421e3312d6b81938edc223b39fb8495948a330927a4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
