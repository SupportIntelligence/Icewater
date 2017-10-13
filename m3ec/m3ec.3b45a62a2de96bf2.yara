import "hash"

rule m3ec_3b45a62a2de96bf2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ec.3b45a62a2de96bf2"
     cluster="m3ec.3b45a62a2de96bf2"
     cluster_size="2962 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="hacktool kmsauto tool"
     md5_hashes="['006bf20f6463934578905a5855ba1e08', '17ebc9874cb231a4c124b80409e33e9b', '1492aa9106126533a0725f615199c042']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(216064,1024) == "80223dd2b6bc15d58b671249a1c05afa"
}

