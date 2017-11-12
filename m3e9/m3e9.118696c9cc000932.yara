import "hash"

rule m3e9_118696c9cc000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.118696c9cc000932"
     cluster="m3e9.118696c9cc000932"
     cluster_size="25686 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['0830f7847e91ec87016fccafa3041068', '072beeaa3390b407815c4b4b98a364ac', '0c343736aba379c1a5881aedce4cced3']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(36864,1024) == "be36e7d837001e86681445cdf3c7723f"
}

