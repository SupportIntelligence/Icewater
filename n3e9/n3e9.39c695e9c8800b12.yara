import "hash"

rule n3e9_39c695e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.39c695e9c8800b12"
     cluster="n3e9.39c695e9c8800b12"
     cluster_size="1059 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="zusy trojandropper backdoor"
     md5_hashes="['a1532c3889b95cb802f48454b40b3583', 'a0e29122df9998aafb2d0b1ccb35cfe7', 'a99cf22e4cf4cc9e83ebb74dc1392a9f']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(138262,1046) == "66a1aad2b922cc836352280ff4cf1d3b"
}

