
rule k2318_1ad15ca9c6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.1ad15ca9c6220b12"
     cluster="k2318.1ad15ca9c6220b12"
     cluster_size="117"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['50e9534e8ec32db4ef3e62e9aec4a92ecd4d78d8','85126e9a8378e251e4a698ec7b2b4ab00b2969f5','81daadd1b478b7f0ed5440c839f554d46fe60307']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.1ad15ca9c6220b12"

   strings:
      $hex_string = { 21646f63747970652068746d6c207075626c696320222d2f2f5733432f2f4454442048544d4c20342e3031205472616e736974696f6e616c2f2f454e223e0a3c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
