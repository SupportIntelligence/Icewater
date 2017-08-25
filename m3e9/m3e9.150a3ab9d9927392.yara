import "hash"

rule m3e9_150a3ab9d9927392
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.150a3ab9d9927392"
     cluster="m3e9.150a3ab9d9927392"
     cluster_size="232 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['aacad3051c1fc45cb109d0f53eb0b9dd', 'a46cb3f72a24908c5dc60807e81d6415', 'cf41d855a7ed1c31fb2a8f1280ef38c8']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(108544,256) == "ef096d58b8311daa24e66b20df439245"
}

