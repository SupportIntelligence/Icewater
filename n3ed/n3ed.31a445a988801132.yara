import "hash"

rule n3ed_31a445a988801132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.31a445a988801132"
     cluster="n3ed.31a445a988801132"
     cluster_size="54 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['d84ad81230999399057da72ba445f5cf', 'a88c50a3b503ba50dfff61b8c23372cd', 'f0abcf20f5a85522b7b89f655a433c84']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(282624,1024) == "5b08fbae40bbe53b0959bc11173e4d2a"
}

