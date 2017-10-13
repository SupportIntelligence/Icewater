import "hash"

rule m3e9_6136a0f969e21932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6136a0f969e21932"
     cluster="m3e9.6136a0f969e21932"
     cluster_size="225 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['fcd66789ca224bcbf06a8d9f8f346085', 'bd374678e0c4ffe694ed0cdd59f96e8d', '367053bdb3ae0fbc624f4c954618831a']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(114176,1024) == "5e2651242e0cc956deeb0dfb4fe18279"
}

