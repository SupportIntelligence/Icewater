import "hash"

rule m3e9_6916d7a9c2000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6916d7a9c2000912"
     cluster="m3e9.6916d7a9c2000912"
     cluster_size="88 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['e213de64ce0803844f9df80509e6f90c', 'cae19a1da96b4fbc293291e65db256bf', 'c124a23b4fbc0803237a00a583f2143c']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(74752,1024) == "9dd737489d4f545899488dd359173093"
}

