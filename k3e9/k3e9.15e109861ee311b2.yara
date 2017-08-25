import "hash"

rule k3e9_15e109861ee311b2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.15e109861ee311b2"
     cluster="k3e9.15e109861ee311b2"
     cluster_size="47 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a43074f466bf0cd4b8d520b3e4c0e9d4', 'b75360d5aa105de6937f5966c22070ff', '16151e220b88c0bb5bcf030233fc3351']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(9472,256) == "a9e75eaf19ede5d0725621845d4bd5d5"
}

