import "hash"

rule k3e9_211c93c9cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.211c93c9cc000b16"
     cluster="k3e9.211c93c9cc000b16"
     cluster_size="725 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['c12405ecf73df384f2b1fec47916546a', 'ab2b007130e921e3290e1b1e4a672168', '4dceca979bf82ecf2b39e24f044af356']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(3096,1048) == "e32607659f107e2d064b4ba17ec9e00c"
}

