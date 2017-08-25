import "hash"

rule k3e9_62149499c2200b00
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.62149499c2200b00"
     cluster="k3e9.62149499c2200b00"
     cluster_size="21 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['e36923e963e1aa8b0362ce79d2bb828d', '90303bff97fd0c3bbbff873d76875a6f', 'a5354bef1e1d0c0641d682354434eaae']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5120,256) == "ef96c463a0314afb568b9965012aec6e"
}

