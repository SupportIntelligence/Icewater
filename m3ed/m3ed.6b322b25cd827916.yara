import "hash"

rule m3ed_6b322b25cd827916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.6b322b25cd827916"
     cluster="m3ed.6b322b25cd827916"
     cluster_size="25 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171018"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['b073f2ea14d7c5688a64138e3af5a5b5', 'bd18a26c2916a334a28263532429550c', 'eb6c1897157a8e38619bb65717a5255c']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 65536 and filesize < 262144
      and hash.md5(83968,1024) == "8d2fafbf55fcfd78b7856bd91338e652"
}

