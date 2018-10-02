
rule k2318_1ad15489c6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.1ad15489c6220b12"
     cluster="k2318.1ad15489c6220b12"
     cluster_size="5064"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['850cf01e156a1f26b65bb2b4140bfdf171b06589','949b3cb051a4eb2b2137bdeddc2ae8e14092858b','18b02fa3746ca40236daf0e19019eaf56df915e9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.1ad15489c6220b12"

   strings:
      $hex_string = { 3c21646f63747970652068746d6c207075626c696320222d2f2f5733432f2f4454442048544d4c20342e3031205472616e736974696f6e616c2f2f454e223e0a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
