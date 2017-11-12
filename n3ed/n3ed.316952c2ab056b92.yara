import "hash"

rule n3ed_316952c2ab056b92
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.316952c2ab056b92"
     cluster="n3ed.316952c2ab056b92"
     cluster_size="851 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="jius heuristic ldpinch"
     md5_hashes="['5283d706ecc8a5720b9addfc577fc70f', '4a64235e5295044889ff76b73438d755', '1f93c3690516fdb3a4985ca4e1a610da']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(170658,1025) == "478623d48021415961554cca04f9d859"
}

