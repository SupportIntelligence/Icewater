import "hash"

rule j3e7_6114f808c2211932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e7.6114f808c2211932"
     cluster="j3e7.6114f808c2211932"
     cluster_size="73 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="corrupt corruptfile heuristic"
     md5_hashes="['df31825e16469c6daeb183fe5660635a', 'a7ee6db9a8621af26889b884a7ba77f5', 'c778154a5d3eb25b9b0d87051d92c6f5']"


   condition:
      filesize > 4096 and filesize < 16384
      and hash.md5(3072,1024) == "1e148258f4d086a8f995c96f0471edc0"
}

