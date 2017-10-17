import "hash"

rule n3e9_499823cbc6620b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.499823cbc6620b16"
     cluster="n3e9.499823cbc6620b16"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy cuegoe malicious"
     md5_hashes="['b3966a2a73946046d70e8e8ba113ec59', '1567dbc23da629920f42dd65adb3935b', 'b3966a2a73946046d70e8e8ba113ec59']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(108544,1024) == "9650727afb29740793894269db598dc4"
}

