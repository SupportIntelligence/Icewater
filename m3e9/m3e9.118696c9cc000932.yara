import "hash"

rule m3e9_118696c9cc000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.118696c9cc000932"
     cluster="m3e9.118696c9cc000932"
     cluster_size="22507 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['04c68cd44845fe5dcafa34a7189f5975', '0080e320c34defecbf8b10cd2a0657e7', '005eac948a272141a9107e3feb96e2ef']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(36864,1024) == "be36e7d837001e86681445cdf3c7723f"
}

