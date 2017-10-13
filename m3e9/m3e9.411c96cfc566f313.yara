import "hash"

rule m3e9_411c96cfc566f313
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.411c96cfc566f313"
     cluster="m3e9.411c96cfc566f313"
     cluster_size="27 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="allaple virut rahack"
     md5_hashes="['c5fee9ed7a4844fcbbf69853116b1d31', 'a323cc9bec1a365598e5a041f1c904fd', 'cd23026a99dd877d7129c0970c582f50']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(178688,1024) == "1596c37d7b83e8d61aec91f1f8c7700f"
}

