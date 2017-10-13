import "hash"

rule m3ed_531403b999646d16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.531403b999646d16"
     cluster="m3ed.531403b999646d16"
     cluster_size="89 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['b7f8dc3eb38a117cbcf0b6aadabf3713', 'b07fa438f30827cbd5bcc4c1e9d14b11', 'e49cab6378188c8621216916832d9d1c']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(138240,1536) == "c125b7c87b1684cc76c8a346e87e9126"
}

