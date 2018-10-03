
rule k2318_33135592dfa30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.33135592dfa30b12"
     cluster="k2318.33135592dfa30b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['e0b33ae34160a52125230a9bd6a8b53d61db9edb','db0dde38b39df0e1342eb9cfe0815262fd3a16e8','5ed9e1445f1226326fc828f6d30ebcb2ec354c8a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.33135592dfa30b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
