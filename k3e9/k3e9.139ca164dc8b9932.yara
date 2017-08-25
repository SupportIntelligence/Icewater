import "hash"

rule k3e9_139ca164dc8b9932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139ca164dc8b9932"
     cluster="k3e9.139ca164dc8b9932"
     cluster_size="8 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['cc0a7af2af85c35de3a5abc0393f4a23', 'cc0a7af2af85c35de3a5abc0393f4a23', 'adb58d50b8aa0d5907abe9820e2ce10c']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(16384,1024) == "a079cfc40f2317e95ff153c3c0dfdaea"
}

