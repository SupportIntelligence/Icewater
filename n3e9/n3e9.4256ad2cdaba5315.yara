import "hash"

rule n3e9_4256ad2cdaba5315
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4256ad2cdaba5315"
     cluster="n3e9.4256ad2cdaba5315"
     cluster_size="3181 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['09f9a0e27f4fa6a770bd7d2c6dc9b8a2', '1829f3acb8e69a4847f951a2f89af6c6', '10c576eafd2f91d86b41a25a4bda89a1']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(712704,1024) == "6e9d1f71c4fc1d15075704839d17b462"
}

