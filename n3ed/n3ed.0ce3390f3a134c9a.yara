import "hash"

rule n3ed_0ce3390f3a134c9a
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.0ce3390f3a134c9a"
     cluster="n3ed.0ce3390f3a134c9a"
     cluster_size="39 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['b8d9014ff1001d470e6c7eeff66aab7f', 'a09e67d48dc2d31b47d22eb73570af61', 'a2ef75ba9a58085186ace643d1645b07']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(635392,1024) == "23ef210ac6a5becc04bd46daffa5e04f"
}

