import "hash"

rule k3e9_6dd119cdde230b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6dd119cdde230b12"
     cluster="k3e9.6dd119cdde230b12"
     cluster_size="53 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="attribute engine highconfidence"
     md5_hashes="['8a2eec7a7bc5bcce2b6bc20e6622afac', 'a6eebe87dc3af2e2db687976eb0c1ef9', 'd7301f3b1fc26037d268a1c15be19bc5']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(31232,1536) == "66b45fceba0f24d768fb09e0afe23c99"
}

