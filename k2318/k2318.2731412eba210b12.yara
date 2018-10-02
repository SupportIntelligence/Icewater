
rule k2318_2731412eba210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.2731412eba210b12"
     cluster="k2318.2731412eba210b12"
     cluster_size="120"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html jscript"
     md5_hashes="['6ee00f118ad474e62cb06926c4d37c8594ff1f26','04f0de287589a931fb82adc3bb0791d831bd86d4','75b794c05cbdf6179021cb4d18a9a820c1e6a54a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.2731412eba210b12"

   strings:
      $hex_string = { 7a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
