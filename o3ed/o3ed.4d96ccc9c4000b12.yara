import "hash"

rule o3ed_4d96ccc9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.4d96ccc9c4000b12"
     cluster="o3ed.4d96ccc9c4000b12"
     cluster_size="231 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['842f6029c033dbd9d35bdad23ec70761', 'a8301962f0b76739685c8efec18b374d', 'b478cb242d413c6418971a57a0968dea']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1173504,1024) == "79a0ca033e9476bdf570bdd896445f12"
}

