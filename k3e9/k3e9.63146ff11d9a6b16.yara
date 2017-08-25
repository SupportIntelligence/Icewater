import "hash"

rule k3e9_63146ff11d9a6b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146ff11d9a6b16"
     cluster="k3e9.63146ff11d9a6b16"
     cluster_size="131 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['be7a9a36e3ee81ae324c803d01f07965', 'c8ea8cc201336b1b1dff1ad4c6760e99', 'cbb05617dfa6d0719f0a25da9b5f4561']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(28672,1024) == "cbe3f2c767bf3f871e1e15b0008153e1"
}

