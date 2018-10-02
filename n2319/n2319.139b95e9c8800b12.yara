
rule n2319_139b95e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.139b95e9c8800b12"
     cluster="n2319.139b95e9c8800b12"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="likejack faceliker clickjack"
     md5_hashes="['50937025f356c382f4327a09b6a74bce126a1618','f5ffa90a668b2cdcd0aa3c1b90973b605c104f16','e6569b78fa6a4781f4e46270ac6192a7b2bc6776']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.139b95e9c8800b12"

   strings:
      $hex_string = { 312f672c2222293b696628212f5e5b2d5f612d7a412d5a302d39232e3a2a202c3e2b7e5b5c5d28293d5e247c5d2b242f2e74657374286329297468726f772045 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
