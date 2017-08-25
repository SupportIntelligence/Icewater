import "hash"

rule k3e9_331c1699c2200b00
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.331c1699c2200b00"
     cluster="k3e9.331c1699c2200b00"
     cluster_size="99 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['e6c8cfbbf54fc9f459dc0fe97f6d7588', 'eed32ea8a95ff35923960af2eb7c40d9', 'c95f73cdbb42e414ad1251159765e3db']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4352,256) == "8faf88ffd3631e972f6bce255f7c9fef"
}

