import "hash"

rule n3ed_595385abc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.595385abc6220b32"
     cluster="n3ed.595385abc6220b32"
     cluster_size="391 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['b1126ca7b94d159218431a4345b6594c', 'c4ef59b07638f7c7fe3bb92afa926fd1', 'ecd7a4bc854059aa2e39485a53969802']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(440662,1109) == "db48825dadc71a665893ba382ddae571"
}

