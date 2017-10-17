import "hash"

rule n3ed_0ca3390f1a0f4932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.0ca3390f1a0f4932"
     cluster="n3ed.0ca3390f1a0f4932"
     cluster_size="117 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['e04eaaa0e18e9454a1a31735fe02988b', 'a14f8f66c5916929a7c0df65ff7db8a1', 'dce8702ffa23fb4be36e38bbc76c5b94']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(635392,1024) == "23ef210ac6a5becc04bd46daffa5e04f"
}

