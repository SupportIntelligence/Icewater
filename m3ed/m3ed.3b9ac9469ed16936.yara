import "hash"

rule m3ed_3b9ac9469ed16936
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.3b9ac9469ed16936"
     cluster="m3ed.3b9ac9469ed16936"
     cluster_size="35 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['cae80780a7fd9c5cd3e75c3951a6a6df', 'd081bf2fb621aa3a4ad1858e1a9772df', 'd1a2b90038b7bcc1162c82036fb47637']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(81920,1024) == "11f70f084ea6711a5d3b6d6fbad3bdbc"
}

