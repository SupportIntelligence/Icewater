import "hash"

rule o3e9_43b0ca9bc2201912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.43b0ca9bc2201912"
     cluster="o3e9.43b0ca9bc2201912"
     cluster_size="7 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['9191d308b81fab99ad1ea43478a56556', 'c35b61675a80841d8aa92f2cd758a824', 'c35b61675a80841d8aa92f2cd758a824']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(728064,1024) == "5a8bb2aaca9ef9a64ba5999efac659f3"
}

