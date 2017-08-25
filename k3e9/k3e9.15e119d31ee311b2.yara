import "hash"

rule k3e9_15e119d31ee311b2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.15e119d31ee311b2"
     cluster="k3e9.15e119d31ee311b2"
     cluster_size="8 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['5bf2d6b2f0f716a999dd06121df245a0', 'cb957e7a301b4d4d526f36a7697f87a4', 'b51b0bd1ccd09838a4f93841de4fb307']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(18432,1024) == "10e9282cad49722b603d799d81e34b3d"
}

