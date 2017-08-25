import "hash"

rule n3e9_010985d6bae31916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.010985d6bae31916"
     cluster="n3e9.010985d6bae31916"
     cluster_size="4710 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="syncopate unwanted malicious"
     md5_hashes="['00fbddfb0b0fc1c86367f4f8b5f198f0', '0c60555faacbae05b2a05cd43cdd7415', '03ebbcf5d5877512e36c9cbc6a9ccf9a']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(565248,1024) == "ead4a97ef9510bb7454b0dd619ef87bd"
}

