import "hash"

rule n3e9_6116fcbcc73ad111
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.6116fcbcc73ad111"
     cluster="n3e9.6116fcbcc73ad111"
     cluster_size="338 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['63b3ce5dd52533765732e333ac4c7bb7', '6aafbdab4cd0cadf22c64c2dd4dbdf3f', 'ef6d7ab032f068349fcf4047393a1651']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(474056,1024) == "da8310b94b651ad74b56b13edc79e850"
}

