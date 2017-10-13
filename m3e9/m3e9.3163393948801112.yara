import "hash"

rule m3e9_3163393948801112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3163393948801112"
     cluster="m3e9.3163393948801112"
     cluster_size="11887 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob sality"
     md5_hashes="['02292f796b6d647528dac4fcfdafcd43', '053a35bf66f7343cf4cdfd2ea8f17a19', '067345a43ba8cd01573e549b91abfe8f']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(4096,1024) == "ccb5dfd1c2cfeaa04f5a58d6701118d9"
}

