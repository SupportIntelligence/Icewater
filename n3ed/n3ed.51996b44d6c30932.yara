import "hash"

rule n3ed_51996b44d6c30932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.51996b44d6c30932"
     cluster="n3ed.51996b44d6c30932"
     cluster_size="68 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['cbd105bc880f7edec1c632547c0b2a6c', 'c3ee536158cbecb4f52b1b899d946639', 'decf1aa013d9302a10b8825f647fc268']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(452608,1024) == "0ddef2dd9490e351383cfa60e754d5ae"
}

