import "hash"

rule k3e9_312eaa4bc6220912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.312eaa4bc6220912"
     cluster="k3e9.312eaa4bc6220912"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob malicious"
     md5_hashes="['47d2b3b2efbf99da7c5c72f866904732', '47d2b3b2efbf99da7c5c72f866904732', 'a814e6bfde714fac711d0cbfeb9a2908']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(1024,1024) == "bafdc1c966710908612de8a0df7c0810"
}

