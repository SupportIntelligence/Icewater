import "hash"

rule o3e9_43b0c9a3c2001912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.43b0c9a3c2001912"
     cluster="o3e9.43b0c9a3c2001912"
     cluster_size="56 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['d2a5d142e57a97409e4292ab330f7171', '61707d56971d59a787c6f63e4fa5c3c7', '61707d56971d59a787c6f63e4fa5c3c7']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(728064,1024) == "5a8bb2aaca9ef9a64ba5999efac659f3"
}

