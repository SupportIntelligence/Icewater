
rule k2318_2313098eae210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.2313098eae210b12"
     cluster="k2318.2313098eae210b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['be5775df041a7efcf371d1e73a2416a4a243d651','d38bce043ca8830238ad5b901be7079f625b0631','11a6fca5fff5ba3151eafe58900cc8f6aa1361c8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.2313098eae210b12"

   strings:
      $hex_string = { 7a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
