import "hash"

rule n3e9_093672a6dfbb1912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.093672a6dfbb1912"
     cluster="n3e9.093672a6dfbb1912"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious fvyj kryptik"
     md5_hashes="['68a80030e168bd938cef5dd0284eb727', '68a80030e168bd938cef5dd0284eb727', '982d4a7c4e55e301a664ff1c4e56fd70']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(647168,1024) == "2a3cbe28e9575b0e98b3d828a8cbed73"
}

