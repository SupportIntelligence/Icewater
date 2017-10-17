import "hash"

rule n3e9_049d96c1c4000932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.049d96c1c4000932"
     cluster="n3e9.049d96c1c4000932"
     cluster_size="50 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="aliser alisa small"
     md5_hashes="['c3927a4b28ea2a03a167b9fe3b7e19df', 'b5fb9d7d036ac365f9a6f9319abdf935', 'a3789ac5d52053fc81975890f98f77f8']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(278528,1024) == "49fedfe9d66be3a6026b41fc3b0e9b08"
}

