import "hash"

rule m3ed_3b9ac9469e916936
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.3b9ac9469e916936"
     cluster="m3ed.3b9ac9469e916936"
     cluster_size="107 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['dadf580c68bbd732801fa817e7a09ffa', '696df6f148563078837db37370f855f2', 'bb10b8f78aadd4ee7b026c075f5f4eae']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(61440,1024) == "fad5720205df679ea754faf4b0429215"
}

