import "hash"

rule k3e9_17e149921ee31132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.17e149921ee31132"
     cluster="k3e9.17e149921ee31132"
     cluster_size="9 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['a29b481d6c23257700f3459a45b075d5', 'c3e72d86c1de7f817825ff49bf076978', 'ac1e5ee0a21123a12f6ff1688c1b2c4a']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(18432,1024) == "10e9282cad49722b603d799d81e34b3d"
}

