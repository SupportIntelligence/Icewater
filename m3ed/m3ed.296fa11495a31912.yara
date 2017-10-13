import "hash"

rule m3ed_296fa11495a31912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.296fa11495a31912"
     cluster="m3ed.296fa11495a31912"
     cluster_size="83 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['bb1a5a282e5b0607c6fbadd08b97e7b3', '098e48368a22d14c9e0d4c134994225c', 'b4b069075e156aed2d98d10359c3d912']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(91136,1098) == "6328c395671af3d442197f887ae83fcf"
}

