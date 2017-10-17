import "hash"

rule k3e7_6134949d42680912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e7.6134949d42680912"
     cluster="k3e7.6134949d42680912"
     cluster_size="194 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit corrupt corruptfile"
     md5_hashes="['b2f9dbe970729f95bcafe670a5a35f70', '0a0a7813178bb8bce6f3075f2ab48d2a', 'fb076245413143efbce3d4a3622da619']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(28672,1024) == "69a512710284c7d66774460d35604e30"
}

