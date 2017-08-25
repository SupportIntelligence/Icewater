import "hash"

rule n3ed_39957a1986620b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.39957a1986620b32"
     cluster="n3ed.39957a1986620b32"
     cluster_size="25 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['eb6a5f00770b4091a6005abc32642744', 'e8ffde1fed74f297accf85ccaa5a4c03', '2453bf1f36fce782b276caac650468db']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(364544,1024) == "59581e811bae19160c9187780d0516d1"
}

