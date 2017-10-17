import "hash"

rule n3ed_5c3ea91cdee31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.5c3ea91cdee31932"
     cluster="n3ed.5c3ea91cdee31932"
     cluster_size="28 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bqjjnb"
     md5_hashes="['a2f0d129bab4bb979fec109326a3461c', '3c6b10a91640dac13d479b3dc754aa7d', 'b65186d41b1b6f506028f13b026ae489']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(332800,1024) == "3eacbc4fc001d21d7f6b60c8cb4d7a59"
}

