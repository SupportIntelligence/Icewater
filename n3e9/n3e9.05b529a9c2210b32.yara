import "hash"

rule n3e9_05b529a9c2210b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.05b529a9c2210b32"
     cluster="n3e9.05b529a9c2210b32"
     cluster_size="757 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="renamer delf grenam"
     md5_hashes="['1f7dcf9ec15873375ab71a5c07f010a4', '1d70f0c4278cf984b51b520a7082370a', '3333fbc9bee647d9a97da9606d801ff2']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(463929,1081) == "87a736d096dd8f6c5aae9a67e116e67e"
}

