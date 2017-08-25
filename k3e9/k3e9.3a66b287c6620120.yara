import "hash"

rule k3e9_3a66b287c6620120
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3a66b287c6620120"
     cluster="k3e9.3a66b287c6620120"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['100f433cf888493f8a8a745849d1afdd', 'bbdca2f9c0e297b6a90b79d08e6e8c98', '100f433cf888493f8a8a745849d1afdd']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4352,256) == "9a1dd280d47f8a52d50d6f78ec240b52"
}

