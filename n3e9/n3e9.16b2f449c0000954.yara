import "hash"

rule n3e9_16b2f449c0000954
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.16b2f449c0000954"
     cluster="n3e9.16b2f449c0000954"
     cluster_size="97 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple virut rahack"
     md5_hashes="['152246c60af38b4c88b05a06047c3556', 'b0bffa9f5278bbcae7d5e17b1989030b', 'de58d5e93a284e9561ffc887800f630d']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(162784,1028) == "4f535038e929bf7b3ba8d207de4f234e"
}

