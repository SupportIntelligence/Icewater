import "hash"

rule k3e9_2b18f3e9c8000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2b18f3e9c8000912"
     cluster="k3e9.2b18f3e9c8000912"
     cluster_size="9 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="razy backdoor simbot"
     md5_hashes="['113bc68c73599e2569cbd495f883f990', 'c2cbee07b97510ca14006fba38486ccc', 'cc2bb01c5ed91da43a11f06bfc526c5c']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(26368,256) == "769fc8de8f491831149e0e56b6e57744"
}

