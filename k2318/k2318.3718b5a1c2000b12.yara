
rule k2318_3718b5a1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3718b5a1c2000b12"
     cluster="k2318.3718b5a1c2000b12"
     cluster_size="18469"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['5c5d69588951988e27752891b253246b80189fbe','ded57a2741966e5b24a57adaf2e716a1cebc4e1c','b26219cdf2d67d3ac161406ea1243e228670e9d4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3718b5a1c2000b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
