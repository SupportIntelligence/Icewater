import "hash"

rule o3e9_099a95b1c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.099a95b1c2200b12"
     cluster="o3e9.099a95b1c2200b12"
     cluster_size="1008 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="noobyprotect advml auto"
     md5_hashes="['480101c356049404f03702571f9bf3bb', '24c9d2abf9262cb4236d00c55c163420', '7ad4aa3f9ee6f28cad2e761443d1fce2']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(105472,1024) == "9458c8b09dab65de465bd0600b093996"
}

