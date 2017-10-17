import "hash"

rule n3ed_31a446cba6221132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.31a446cba6221132"
     cluster="n3ed.31a446cba6221132"
     cluster_size="112 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['c56ebd18c1931c1a72dada431262b519', 'b704cc2f962642a7f3ed6a64367f148f', 'df25a03fbb1e9ca22c301f27d3431786']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(282624,1024) == "5b08fbae40bbe53b0959bc11173e4d2a"
}

