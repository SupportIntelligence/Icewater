import "hash"

rule o3ed_539c16cfce220b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.539c16cfce220b12"
     cluster="o3ed.539c16cfce220b12"
     cluster_size="133 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['b700f978a148b926eb8c58af1dc26bb9', 'cd5c2eadfbba4c3db465a9e723629b05', 'c436d4a3bbb998c20bf321c3df21a7ed']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(622592,1024) == "a284980dc8bff1ac8a5e368a4d72e412"
}

