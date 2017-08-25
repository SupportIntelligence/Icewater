import "hash"

rule n3e9_408c2bd9cc010932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.408c2bd9cc010932"
     cluster="n3e9.408c2bd9cc010932"
     cluster_size="329 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="sality autorun emailworm"
     md5_hashes="['9d9bc61b9cef5f43670043827ff067cb', '3fdafaca16698720a8f67591e9786b6b', 'd73de5b63d2f051059d16434063a3e25']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(25600,1024) == "62c0bfc887217c8ea97cd11be105f8e0"
}

